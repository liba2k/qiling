#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import ctypes
import types
import struct
from unicorn import *
from unicorn.x86_const import *
from qiling.const import *
from qiling.os.os import QlOs

class QlOsUefi(QlOs):
    # Cehck access from emulation
    def check_smm_ram_access(ql, access, addr, size, value):
        if ql.os.InSmm == 0:
            raise(Exception(f'check_smm_ram_access - {access}, {addr}, {size}, {value}'))
    
    # Check access from python hooks.
    @property
    def smbase(self):
        if not self.running_init and self.InSmm == 0:
            raise(Exception('Getting smbase while not in SMM'))
        return self.__smbase
    
    @smbase.setter
    def smbase(self, smbase):
        if not self.running_init:
            raise(Exception('Setting smbase after init'))
        self.__smbase = smbase

    def __init__(self, ql):
        super(QlOsUefi, self).__init__(ql)
        self.running_init = True
        self.ql = ql
        self.entry_point = 0
        self.user_defined_api = {}
        self.user_defined_api_onenter = {}
        self.user_defined_api_onexit = {}
        self.notify_immediately = False
        self.PE_RUN = True
        self.InSmm = 0
        self.smbase = int(self.profile.get("SMM", "smbase"), 16)
        self.smram_size = int(self.profile.get("SMM", "smram_size"), 16)
        ql.mem.map(self.smbase, self.smram_size)
        ql.hook_mem_read(self.check_smm_ram_access, user_data=None, begin=self.smbase, end=self.smbase+self.smram_size)
        ql.hook_mem_write(self.check_smm_ram_access, user_data=None, begin=self.smbase, end=self.smbase+self.smram_size)
        ql.hook_mem_fetch(self.check_smm_ram_access, user_data=None, begin=self.smbase, end=self.smbase+self.smram_size)
        self.running_init = False
    
    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point
        
        if  self.ql.entry_point  is not None:
            self.ql.loader.entry_point = self.ql.entry_point

        try:
            self.ql.emu_start(self.ql.loader.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
        except UcError:
            self.emu_error()
            raise

        if self.ql.internal_exception is not None:
            raise self.ql.internal_exception


