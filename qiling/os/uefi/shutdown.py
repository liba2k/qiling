#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .utils import *
from qiling.os.uefi.type64 import EFI_GUID
from qiling.os.uefi.smm_sw_dispatch2_protocol import trigger_swsmi
from ctypes import *

class ArgsForOperation(Structure):
    _fields_ = [
        ("Guid", EFI_GUID),
        ("pVarName", c_uint32),
        ("pAttributes", c_uint32),
        ("pDataSize", c_uint32),
        ("pDestBuffer", c_uint32)
    ]

def hook_EndOfExecution(ql):
    ql.os.InSmm = 0 # We always leave SMM when switching between modules.
    ql.loader.restore_runtime_services()
    if check_and_notify_protocols(ql):
        return
    if len(ql.loader.modules) < 1:
        if ql.loader.should_trigger_swsmi:
            ql.loader.should_trigger_swsmi = False

            pVarName = ql.mem.map_anywhere(16)
            ql.mem.write(pVarName, b"Setup")

            pDataSize = ql.mem.map_anywhere(16)
            ql.mem.write(pDataSize, b"\x01\x00\x00\x00")

            argsForOperation = ArgsForOperation()
            argsForOperation.pVarName = pVarName
            argsForOperation.pAttributes = 0
            argsForOperation.pDataSize = pDataSize
            argsForOperation.pDestBuffer = pVarName

            # Write params structure to memory
            paramsForOperationsAddr = ql.mem.map_anywhere(sizeof(argsForOperation))
            ql.mem.write(paramsForOperationsAddr, bytes(argsForOperation))

            buff = ql.mem.map_anywhere(16)
            ql.mem.write(buff, b"\x00\x01\x00\x00" + paramsForOperationsAddr.to_bytes(8, 'little'))
            
            ql.stack_push(ql.loader.end_of_execution_ptr)
            trigger_swsmi(ql, {'rsi': buff})
            ql.reg.arch_pc = ql.stack_pop()
            return

        if ql.loader.unload_modules():
            return
        ql.nprint(f'[+] No more modules to run')
        ql.emu_stop()
    else:
        ql.loader.execute_next_module()

def hook_OutOfOrder_EndOfExecution(ql):
    # X64 shadow store - The caller is responsible for allocating space for parameters to the callee, and must always allocate sufficient space to store four register parameters
    ql.reg.rsp += pointer_size * 4
    return_address = ql.stack_pop()
    ql.nprint(f'[+] Back from out of order call, returning to:0x{return_address:x}')
    ql.reg.arch_pc = return_address

    callback_ctx = ql.loader.OOO_EOE_callbacks.pop()
    if callback_ctx is not None:
        func, ql, address, params = callback_ctx
        return func(ql, address, params)
    return 0


