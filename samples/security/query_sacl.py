import sys
import windows.security

TARGET = r"C:\windows\notepad.exe" # On WIN10 (at least) notepad.exe has a AuditACE

if not windows.current_process.token.elevated:
    print(ValueError("This sample should be run as admin to demonstration SACL access"))

print("")
print("[NO-PRIV] Querying <{0}> SecurityDescriptor without SACL".format(TARGET))
sd = windows.security.SecurityDescriptor.from_filename(TARGET)
print("sacl = {0}".format(sd.sacl))

print("")
print("[NO-PRIV] Querying <{0}> SecurityDescriptor with SACL".format(TARGET))
try:
    sd = windows.security.SecurityDescriptor.from_filename(TARGET, query_sacl=True)
    print("sacl = {0}".format(sd.sacl))
except WindowsError as e:
    print(e)

print("")
print("Enabling <SeSecurityPrivilege>")
try:
    windows.current_process.token.enable_privilege("SeSecurityPrivilege")
except ValueError as e:
    print("[ERROR] {0}".format(e))
    exit(1)

print("")
print("[PRIV] Querying <{0}> SecurityDescriptor with SACL".format(TARGET))
sd = windows.security.SecurityDescriptor.from_filename(TARGET, query_sacl=True)
print("sacl = {0}".format(sd.sacl))
print(list(sd.sacl))