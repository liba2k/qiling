#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import sys
import pickle
sys.path.append("..")
from qiling import *

# @dxeapi(params={
#     "Protocol": GUID,
#     "Event": POINTER,
#     "Registration": POINTER})
def force_notify_RegisterProtocolNotify(self, address, params):
    event_id = params['Event']
    if event_id in self.ql.events:
        self.ql.events[event_id]['Guid'] = params["Protocol"]
        # let's force notify
        event = self.ql.events[event_id]
        event["Set"] = True
        self.ql.notify_list.append((event_id, event['NotifyFunction'], event['NotifyContext']))
        ######
        return self.EFI_SUCCESS
    return self.EFI_INVALID_PARAMETER


if __name__ == "__main__":
    with open("rootfs/x8664_efi/rom2_nvar.pickel", 'rb') as f:
        env = pickle.load(f)
    ql = Qiling(["rootfs/x8664_efi/bin/TcgPlatformSetupPolicy"], "rootfs/x8664_efi", env=env)
    ql.hook_override["hook_RegisterProtocolNotify"] = force_notify_RegisterProtocolNotify
    ql.run()