import argparse
import os.path

import windows.security



parser = argparse.ArgumentParser(prog=__file__)
parser.add_argument('sddl', help='The SDDL to explain')
parser.add_argument('--type', help='The type of object described by the SDDL (used for the explication of values in the access mask)')
res = parser.parse_args()

if os.path.exists(res.sddl):
    windows.security.SecurityDescriptor.from_filename(res.sddl).explain("file")
else:
    windows.security.SecurityDescriptor.from_string(res.sddl).explain(res.type)
