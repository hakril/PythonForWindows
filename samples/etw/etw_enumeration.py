import windows

etwmgr = windows.system.etw

print("ETW Manager is: {0}".format(etwmgr))

print("")
print("Listing some ETW sessions:")
for sess in etwmgr.sessions[:2]:
    print("  * {0}".format(sess))
    print("     * name: {0}".format(sess.name))
    print("     * guid: {0}".format(sess.guid))
    print("     * id: {0}".format(sess.id))
    print("     * logfile: {0}".format(sess.logfile))

target_id = sess.id
NB_MATCH = 0
print("")
print("Looking for providers for: {0}".format(sess))
for provider in windows.system.etw.providers:
    if NB_MATCH == 3:
        break
    for instance in provider.instances:
        if NB_MATCH == 3:
            break
        for session in instance.sessions:
            if session.LoggerId == target_id and instance.Pid:
                proc = [p for p in windows.system.processes if p.pid == instance.Pid][0]
                print("Found a provider/session for target:")
                print("  * Provider: {0}".format(provider))
                print("  * Instance: {0}".format(instance))
                print("  * Process: {0}".format(proc))
                NB_MATCH += 1
                if NB_MATCH == 3:
                    break
                break
