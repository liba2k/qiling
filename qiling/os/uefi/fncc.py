#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from qiling.const import *
from qiling.os.windows.utils import read_cstring, read_wstring, read_guid, print_function

DWORD = 1
UINT = 1
INT = 1
BOOL = 1
SIZE_T = 1
BYTE = 1
ULONGLONG = 2
HANDLE = 3
POINTER = 3
STRING = 4
WSTRING = 5
STRING_ADDR = 6
WSTRING_ADDR = 7
GUID = 8

def get_param_by_index(ql, index):
    if ql.archtype == QL_ARCH.X86:
        return _x86_get_params_by_index(ql, index)
    elif ql.archtype == QL_ARCH.X8664:
        return _x8664_get_params_by_index(ql, index)

def _x86_get_params_by_index(ql, index):
    # index starts from 0
    # skip ret_addr
    return ql.stack_read((index + 1) * 4)

def _x8664_get_params_by_index(ql, index):
    reg_list = ["rcx", "rdx", "r8", "r9"]
    if index < 4:
        return ql.reg.read(reg_list[index])

    index -= 4
    # skip ret_addr
    return ql.stack_read((index + 5) * 8)

def set_return_value(ql, ret):
    if ql.archtype == QL_ARCH.X86:
        ql.reg.eax = ret
    elif ql.archtype == QL_ARCH.X8664:
        ql.reg.rax = ret

def set_function_params(ql, in_params, out_params):
    index = 0
    for each in in_params:
        if in_params[each] == DWORD or in_params[each] == POINTER:
            out_params[each] = get_param_by_index(ql, index)
        elif in_params[each] == ULONGLONG:
            if ql.archtype == QL_ARCH.X86:
                low = get_param_by_index(ql, index)
                index += 1
                high = get_param_by_index(ql, index)
                out_params[each] = high << 32 + low
            else:
                out_params[each] = get_param_by_index(ql, index)
        elif in_params[each] == STRING or in_params[each] == STRING_ADDR:
            ptr = get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                content = read_cstring(ql, ptr)
                if in_params[each] == STRING_ADDR:
                    out_params[each] = (ptr, content)
                else:
                    out_params[each] = content
        elif in_params[each] == WSTRING or in_params[each] == WSTRING_ADDR:
            ptr = get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                content = read_wstring(ql, ptr)
                if in_params[each] == WSTRING_ADDR:
                    out_params[each] = (ptr, content)
                else:
                    out_params[each] = content
        elif in_params[each] == GUID:
            ptr = get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                out_params[each] = str(read_guid(ql, ptr))
        index += 1
    return index

def __x86_cc(ql, param_num, params, func, args, kwargs):
    # read params
    if params is not None:
        param_num = set_function_params(ql, params, args[2])
    # call function
    result = func(*args, **kwargs)

    # set return value
    if result is not None:
        set_return_value(ql, result)
    # print
    print_function(ql, args[1], func.__name__, args[2], result)

    return result, param_num



def _call_api(ql, name, params, result, address, return_address):
    params_with_values = {}
    if name.startswith("hook_"):
        name = name.split("hook_", 1)[1]
        # printfs are shit
        if params is not None:
            set_function_params(ql, params, params_with_values)
    ql.os.syscalls.setdefault(name, []).append({
        "params": params_with_values,
        "result": result,
        "address": address,
        "return_address": return_address,
        "position": ql.os.syscalls_counter
    })

    ql.os.syscalls_counter += 1

def x8664_fastcall(ql, param_num, params, func, args, kwargs):
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)
    old_pc = ql.reg.arch_pc
    # append syscall to list
    _call_api(ql, func.__name__, params, result, old_pc, ql.stack_read(0))

    if ql.os.PE_RUN:
        ql.reg.arch_pc = ql.stack_pop()

    return result

def dxeapi(param_num=None, params=None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            ql = args[0]
            arg = (ql, ql.reg.arch_pc, {})
            f = func
            if func.__name__ in ql.loader.hook_override:
                f = ql.loader.hook_override[func.__name__]
            return x8664_fastcall(ql, param_num, params, f, arg, kwargs)

        return wrapper

    return decorator
