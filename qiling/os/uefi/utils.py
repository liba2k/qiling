import ctypes
import struct
from qiling.const import *

def write_int32(ql, address, num):
    if ql.archendian == QL_ENDIAN.EL:
        ql.mem.write(address, struct.pack('<I',(num)))
    else:
        ql.mem.write(address, struct.pack('>I',(num)))

def write_int64(ql, address, num):
    if ql.archendian == QL_ENDIAN.EL:
        ql.mem.write(address, struct.pack('<Q',(num)))
    else:
        ql.mem.write(address, struct.pack('>Q',(num)))

def read_int64(ql, address):
    if ql.archendian == QL_ENDIAN.EL:
        return struct.unpack('<Q', ql.mem.read(address, 8))[0]
    else:
        return struct.unpack('>Q',ql.mem.read(address, 8))[0]

def convert_struct_to_bytes(st):
    buffer = ctypes.create_string_buffer(ctypes.sizeof(st))
    ctypes.memmove(buffer, ctypes.addressof(st), ctypes.sizeof(st))
    return buffer.raw
