import windows.security

SDDL = "O:BAG:AND:(A;OI;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)(D;CIIO;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)"

sd = windows.security.SecurityDescriptor.from_string(SDDL)
print("Security descriptor is: {0}".format(sd))

print("Owner: {0}".format(sd.owner))
print("  - lookup: {0}".format(windows.security.lookup_sid(sd.owner)))
print("Group: {0}".format(sd.group))
print("  - lookup: {0}".format(windows.security.lookup_sid(sd.group)))

dacl = sd.dacl
print("Dacl: {0}".format(dacl))

for i, ace in enumerate(dacl):
    print("")
    print("  ACE [{0}]: {1}".format(i, ace))
    print("    - Header-AceType: {0}".format(ace.Header.AceType))
    print("    - Header-AceFlags: {0}".format(ace.Header.AceFlags))
    print("    - Header-flags: {0}".format(ace.Header.flags))
    print("    - Mask: {0}".format(ace.Mask))
    print("    - mask: {0}".format(ace.mask))
    print("    - Sid:  {0}".format(ace.sid))