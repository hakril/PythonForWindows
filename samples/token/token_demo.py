import windows
import windows.generated_def as gdef

tok = windows.current_process.token
print("Our process token is {0}".format(tok))
print("Retrieving some infos")
print("Username: <{0}>".format(tok.username))
print("User: {0!r}".format(tok.user))
print("  - lookup : {0}".format(windows.utils.lookup_sid(tok.user)))
print("Primary group: {0!r}".format(tok.primary_group))
print("  - lookup : {0}".format(windows.utils.lookup_sid(tok.primary_group)))

print("")
groups = tok.groups
print("Token Groups is {0}".format(groups))
print("First group SID is {0!r}".format(groups.sids[0]))
print("Some sid and attributes:")
for i, group in zip(range(3), groups.sids_and_attributes):
    print(" - {0}: {1}".format(group.Sid, group.Attributes))

# Let's play with duplicate !
print("")
imp_tok = tok.duplicate(type=gdef.TokenImpersonation, impersonation_level=gdef.SecurityImpersonation)
print("Duplicate token is {0}".format(imp_tok))
print("Enabling <SeShutDownPrivilege>")
imp_tok.enable_privilege("SeShutDownPrivilege")

cur_thread = windows.current_thread
print("Current thread token is <{0}>".format(cur_thread.token))
print("Setting impersonation token !")
cur_thread.token = imp_tok
print("Current thread token is {0}".format(cur_thread.token))
