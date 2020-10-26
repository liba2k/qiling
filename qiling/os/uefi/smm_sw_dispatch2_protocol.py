from qiling.const import *
from qiling.os.const import *
from .const import *
from .utils import *
from .smm_sw_dispatch2_type import *
from .fncc import *

pointer_size = ctypes.sizeof(ctypes.c_void_p)

smram = 0

def free_pointers(ql, address, params):
    print("free pointers called")
    ql.os.heap.free(address)
    return EFI_SUCCESS

smi_handlers = []

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "DispatchFunction": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
    "RegisterContext": POINTER, #POINTER_T(struct_EFI_SMM_SW_REGISTER_CONTEXT)
    "DispatchHandle": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_SMM_SW_DISPATCH2_Register(ql, address, params):
    smi_handlers.append(params)
    # Since we are not really in smm mode, we can just call the function from here
    # ql.reg.rsp -= pointer_size * 4
    # ql.stack_push(ql.loader.OOO_EOE_ptr)  # Return address from the notify function.
    # ql.stack_push(params["DispatchFunction"])  # Return address from here -> the dispatch function.
    # out_pointers = ql.os.heap.alloc(pointer_size * 2)
    # ql.loader.OOO_EOE_callbacks.append(
    #     (free_pointers, ql, out_pointers, params))  # We don't need a callback.
    # ql.reg.rcx = params["DispatchHandle"]
    # ql.reg.rdx = params["RegisterContext"]
    # ql.reg.r8 = out_pointers  # OUT VOID    *CommBuffer
    # ql.reg.r9 = out_pointers + pointer_size  # OUT UINTN   *CommBufferSize

    
@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "DispatchHandle": POINTER, #POINTER_T(None)
})
def hook_SMM_SW_DISPATCH2_UnRegister(ql, address, params):
    return EFI_SUCCESS



def install_EFI_SMM_SW_DISPATCH2_PROTOCOL(ql, start_ptr):
    efi_smm_sw_dispatch2_protocol = EFI_SMM_SW_DISPATCH2_PROTOCOL()
    ptr = start_ptr
    pointer_size = 8
    efi_smm_sw_dispatch2_protocol.Register = ptr
    ql.hook_address(hook_SMM_SW_DISPATCH2_Register, ptr)
    ptr += pointer_size
    efi_smm_sw_dispatch2_protocol.UnRegister = ptr
    ql.hook_address(hook_SMM_SW_DISPATCH2_UnRegister, ptr)
    ptr += pointer_size
    return (ptr, efi_smm_sw_dispatch2_protocol)

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "Width": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
    "Register": POINTER, #POINTER_T(struct_EFI_SMM_SW_REGISTER_CONTEXT)
    "CpuIndex": POINTER, #POINTER_T(POINTER_T(None))
    "Buffer": POINTER,
})
def hook_SMM_CPU_ReadSaveState(ql, address, params):
    # Since we are not really in smm mode, we can just call the function from here

    # make a table for mapping register ids to offsets
    EFI_SMM_SAVE_STATE_REGISTER_GDTBASE = 4
    EFI_SMM_SAVE_STATE_REGISTER_IDTBASE = 5
    EFI_SMM_SAVE_STATE_REGISTER_LDTBASE = 6
    EFI_SMM_SAVE_STATE_REGISTER_GDTLIMIT = 7
    EFI_SMM_SAVE_STATE_REGISTER_IDTLIMIT = 8
    EFI_SMM_SAVE_STATE_REGISTER_LDTLIMIT = 9
    EFI_SMM_SAVE_STATE_REGISTER_LDTINFO = 10
    EFI_SMM_SAVE_STATE_REGISTER_ES = 20
    EFI_SMM_SAVE_STATE_REGISTER_CS = 21
    EFI_SMM_SAVE_STATE_REGISTER_SS = 22
    EFI_SMM_SAVE_STATE_REGISTER_DS = 23
    EFI_SMM_SAVE_STATE_REGISTER_FS = 24
    EFI_SMM_SAVE_STATE_REGISTER_GS = 25
    EFI_SMM_SAVE_STATE_REGISTER_LDTR_SEL = 26
    EFI_SMM_SAVE_STATE_REGISTER_TR_SEL = 27
    EFI_SMM_SAVE_STATE_REGISTER_DR7 = 28
    EFI_SMM_SAVE_STATE_REGISTER_DR6 = 29
    EFI_SMM_SAVE_STATE_REGISTER_R8 = 30
    EFI_SMM_SAVE_STATE_REGISTER_R9 = 31
    EFI_SMM_SAVE_STATE_REGISTER_R10 = 32
    EFI_SMM_SAVE_STATE_REGISTER_R11 = 33
    EFI_SMM_SAVE_STATE_REGISTER_R12 = 34
    EFI_SMM_SAVE_STATE_REGISTER_R13 = 35
    EFI_SMM_SAVE_STATE_REGISTER_R14 = 36
    EFI_SMM_SAVE_STATE_REGISTER_R15 = 37
    EFI_SMM_SAVE_STATE_REGISTER_RAX = 38
    EFI_SMM_SAVE_STATE_REGISTER_RBX = 39
    EFI_SMM_SAVE_STATE_REGISTER_RCX = 40
    EFI_SMM_SAVE_STATE_REGISTER_RDX = 41
    EFI_SMM_SAVE_STATE_REGISTER_RSP = 42
    EFI_SMM_SAVE_STATE_REGISTER_RBP = 43
    EFI_SMM_SAVE_STATE_REGISTER_RSI = 44
    EFI_SMM_SAVE_STATE_REGISTER_RDI = 45
    EFI_SMM_SAVE_STATE_REGISTER_RIP = 46
    EFI_SMM_SAVE_STATE_REGISTER_RFLAGS = 51
    EFI_SMM_SAVE_STATE_REGISTER_CR0 = 52
    EFI_SMM_SAVE_STATE_REGISTER_CR3 = 53
    EFI_SMM_SAVE_STATE_REGISTER_CR4 = 54
    EFI_SMM_SAVE_STATE_REGISTER_FCW = 256
    EFI_SMM_SAVE_STATE_REGISTER_FSW = 257
    EFI_SMM_SAVE_STATE_REGISTER_FTW = 258
    EFI_SMM_SAVE_STATE_REGISTER_OPCODE = 259
    EFI_SMM_SAVE_STATE_REGISTER_FP_EIP = 260
    EFI_SMM_SAVE_STATE_REGISTER_FP_CS = 261
    EFI_SMM_SAVE_STATE_REGISTER_DATAOFFSET = 262
    EFI_SMM_SAVE_STATE_REGISTER_FP_DS = 263
    EFI_SMM_SAVE_STATE_REGISTER_MM0 = 264
    EFI_SMM_SAVE_STATE_REGISTER_MM1 = 265
    EFI_SMM_SAVE_STATE_REGISTER_MM2 = 266
    EFI_SMM_SAVE_STATE_REGISTER_MM3 = 267
    EFI_SMM_SAVE_STATE_REGISTER_MM4 = 268
    EFI_SMM_SAVE_STATE_REGISTER_MM5 = 269
    EFI_SMM_SAVE_STATE_REGISTER_MM6 = 270
    EFI_SMM_SAVE_STATE_REGISTER_MM7 = 271
    EFI_SMM_SAVE_STATE_REGISTER_XMM0 = 272
    EFI_SMM_SAVE_STATE_REGISTER_XMM1 = 273
    EFI_SMM_SAVE_STATE_REGISTER_XMM2 = 274
    EFI_SMM_SAVE_STATE_REGISTER_XMM3 = 275
    EFI_SMM_SAVE_STATE_REGISTER_XMM4 = 276
    EFI_SMM_SAVE_STATE_REGISTER_XMM5 = 277
    EFI_SMM_SAVE_STATE_REGISTER_XMM6 = 278
    EFI_SMM_SAVE_STATE_REGISTER_XMM7 = 279
    EFI_SMM_SAVE_STATE_REGISTER_XMM8 = 280
    EFI_SMM_SAVE_STATE_REGISTER_XMM9 = 281
    EFI_SMM_SAVE_STATE_REGISTER_XMM10 = 282
    EFI_SMM_SAVE_STATE_REGISTER_XMM11 = 283
    EFI_SMM_SAVE_STATE_REGISTER_XMM12 = 284
    EFI_SMM_SAVE_STATE_REGISTER_XMM13 = 285
    EFI_SMM_SAVE_STATE_REGISTER_XMM14 = 286
    EFI_SMM_SAVE_STATE_REGISTER_XMM15 = 287
    EFI_SMM_SAVE_STATE_REGISTER_IO = 512
    EFI_SMM_SAVE_STATE_REGISTER_LMA = 513
    EFI_SMM_SAVE_STATE_REGISTER_PROCESSOR_ID = 514

    offsets = {
        EFI_SMM_SAVE_STATE_REGISTER_RSI: 0x7f8c,
    }

    import ipdb; ipdb.set_trace()
    # Find start of smram
    # save_state = smram + 0x8000
    # add the offset the current offset
    # read the register
    addr = smram + 0x8000 + offsets[params["Register"]]
    reg = ql.mem.read(addr, params["Width"])
    ql.mem.write(params["Buffer"], bytes(reg))

    return EFI_SUCCESS

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "Width": UINTN, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
    "Register": ctypes.c_uint32, #POINTER_T(struct_EFI_SMM_SW_REGISTER_CONTEXT)
    "CpuIndex": UINTN, #POINTER_T(POINTER_T(None))
    "Buffer": POINTER,
})
def hook_SMM_CPU_WriteSaveState(ql, address, params):
    # Since we are not really in smm mode, we can just call the function from here
    import ipdb; ipdb.set_trace()

def install_EFI_SMM_CPU_PROTOCOL(ql, start_ptr):
    efi_smm_cpu_protocol = EFI_SMM_CPU_PROTOCOL()
    ptr = start_ptr
    pointer_size = 8
    efi_smm_cpu_protocol.ReadSaveState = ptr
    ql.hook_address(hook_SMM_CPU_ReadSaveState, ptr)
    ptr += pointer_size
    efi_smm_cpu_protocol.WriteSaveState = ptr
    ql.hook_address(hook_SMM_CPU_WriteSaveState, ptr)
    ptr += pointer_size
    return (ptr, efi_smm_cpu_protocol)

def call_smi_handlers(ql):

    for smi_params in smi_handlers:
        print(f"Executing SMI with params {smi_params}")
        out_pointers = ql.os.heap.alloc(pointer_size * 2)

        ql.reg.rcx = smi_params["DispatchHandle"]
        ql.reg.rdx = smi_params["RegisterContext"]
        ql.reg.r8 = out_pointers  # OUT VOID    *CommBuffer
        ql.reg.r9 = out_pointers + pointer_size  # OUT UINTN   *CommBufferSize

        code = """
            mov rax, {0}
            call rax
            """.format(smi_params["DispatchFunction"])

        runcode = ql.compile(ql.archtype, code)
        ptr = ql.os.heap.alloc(len(runcode))
        ql.mem.write(ptr, runcode)
        ql.os.exec_arbitrary(ptr, ptr + len(runcode))


        # # Since we are not really in smm mode, we can just call the function from here
        # ql.reg.rsp -= pointer_size * 4
        # ql.stack_push(ql.loader.OOO_EOE_ptr) # Return address from the notify function.
        # ql.stack_push(smi_params["DispatchFunction"]) # Return address from here -> the dispatch function.
        #
        # ql.loader.OOO_EOE_callbacks.append((free_pointers, ql, out_pointers, smi_params)) # We don't need a callback.

def trigger_swsmi(ql, user_data=None):

    ql.reg.rsi = user_data['rsi']

    global smram
    # import ipdb; ipdb.set_trace()
    # Allocate and initialize SMRAM
    # smbase = int(ql.os.profile.get("SMM", "smbase"), 16)
    smram_size = int(ql.os.profile.get("SMM", "smram_size"), 16)
    # smram = ql.mem.map(smbase, smram_size)
    smram = ql.mem.map_anywhere(smram_size)
    smbase = smram

    # import ipdb; ipdb.set_trace()
    # ql.os.emu_error()

    # Copy all arguments to the save state
    ql.mem.write(smbase + 0x8000 + 0x7ff8, ql.reg.cr0.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7ff0, ql.reg.cr3.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7fe8, ql.reg.ef.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7fe0, (0).to_bytes(8, 'little')) # IA32_EFER
    ql.mem.write(smbase + 0x8000 + 0x7fd8, ql.reg.rip.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7fd0, (0).to_bytes(8, 'little')) # DR6
    ql.mem.write(smbase + 0x8000 + 0x7fc8, (0).to_bytes(8, 'little')) # DR7
    ql.mem.write(smbase + 0x8000 + 0x7fc4, (0).to_bytes(4, 'little'))  # TR SEL
    ql.mem.write(smbase + 0x8000 + 0x7fc0, (0).to_bytes(4, 'little'))  # LDTR SEL
    ql.mem.write(smbase + 0x8000 + 0x7fbc, (0).to_bytes(4, 'little'))  # GS SEL
    ql.mem.write(smbase + 0x8000 + 0x7fbc, ql.reg.gs.to_bytes(4, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7fb8, ql.reg.fs.to_bytes(4, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7fb4, ql.reg.ds.to_bytes(4, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7fb0, ql.reg.ss.to_bytes(4, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7fac, ql.reg.cs.to_bytes(4, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7fa8, ql.reg.es.to_bytes(4, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7fa4, (0).to_bytes(4, 'little')) # IO MISC
    ql.mem.write(smbase + 0x8000 + 0x7f9c, (0).to_bytes(8, 'little'))  # IO MEM ADDR
    ql.mem.write(smbase + 0x8000 + 0x7f94, ql.reg.rdi.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f8c, ql.reg.rsi.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f84, ql.reg.rbp.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f7c, ql.reg.rsp.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f74, ql.reg.rbx.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f6c, ql.reg.rdx.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f64, ql.reg.rcx.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f5c, ql.reg.rax.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f54, ql.reg.r8.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f4c, ql.reg.r9.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f44, ql.reg.r10.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f3c, ql.reg.r11.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f34, ql.reg.r12.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f2c, ql.reg.r13.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f24, ql.reg.r14.to_bytes(8, 'little'))
    ql.mem.write(smbase + 0x8000 + 0x7f1c, ql.reg.r15.to_bytes(8, 'little'))
    # Rest will follow here

    # Set InSmm to TRUE
    # Call the dispatcher
    call_smi_handlers(ql)
