#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .utils import *
from qiling.os.uefi.smm_sw_dispatch2_protocol import trigger_swsmi

def hook_EndOfExecution(ql):
    ql.loader.restore_runtime_services()
    if check_and_notify_protocols(ql):
        return
    if len(ql.loader.modules) < 1:
        if ql.loader.should_trigger_swsmi:
            ql.loader.should_trigger_swsmi = False
            paramsForOperations = ql.mem.map_anywhere(64)
            # Write GUID
            ql.mem.write(paramsForOperations, b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\aa\xbb\xcc\xdd\xee\xff")
            paramsForOperationsAddr = paramsForOperations.to_bytes(8, 'little')
            buff = ql.mem.map_anywhere(16)
            ql.mem.write(buff, b"\x00\x01\x00\x00" + paramsForOperationsAddr)
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


