import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows.wintrust

TARGET_FILE = r"C:\windows\system32\ntdll.dll"
print("Checking signature of <{0}>".format(TARGET_FILE))
print(" is_signed: <{0}>".format(windows.wintrust.is_signed(TARGET_FILE)))
print(" check_signature: <{0}>".format(windows.wintrust.check_signature(TARGET_FILE)))

sign_info = windows.wintrust.full_signature_information(TARGET_FILE)
print(" full_signature_information:")
print("    * signed <{0}>".format(sign_info.signed))
print("    * catalog <{0}>".format(sign_info.catalog))
print("    * catalogsigned <{0}>".format(sign_info.catalogsigned))
print("    * additionalinfo <{0}>".format(sign_info.additionalinfo))

print("Checking signature of some loaded DLL")
for module in windows.current_process.peb.modules[:5]:
    path = module.fullname
    is_signed =  windows.wintrust.is_signed(path)
    if is_signed:
        print("<{0}> : {1}".format(path, is_signed))
    else:
        sign_info = windows.wintrust.full_signature_information(path)
        print("<{0}> : {1} ({2})".format(path, is_signed, sign_info[3]))


