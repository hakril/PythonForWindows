import windows
import windows.generated_def as gdef

manager = windows.system.device_manager
print(manager)
for devcls in manager.classes:
    print("- {0!r}".format(devcls))
    for device in devcls.devices:
        print(u"    - [{dev.name}] <{dev.description}> ({dev.device_object_name})".format(dev=device))
        # Je sais pas trop quoi faire comme API sur ce truc
        # Apparement on peut avoir plusieurs logical_configuration par type
        #   - Je sais meme pas si c'est possible en vrai meme si <CM_Get_Next_Log_Conf> existe
        # Idées:
        #   * get_allocated_conf + get_boot_conf & co
        #   * logical_configurations() qui retourne la liste complete
        #   * Je sais pas trop
        #
        devconf = device.get_first_logical_configuration(gdef.ALLOC_LOG_CONF)
        if devconf:
            # import pdb;pdb.set_trace()
            # print(devconf)
            print("      <config:>")
            for resource in devconf.resources:
                print("        - {0}".format(resource))

        # print(dev.description)
        # print(dev.device_object_name)
        # # x = dev.get_first_logical_configuration(gdef.ALLOC_LOG_CONF)
        # x = dev.get_first_logical_configuration(gdef.BOOT_LOG_CONF)
        # if x:
        #     print(x)
        #     for res in x.resources:
        #         print(res)
        #         # print(repr(res.rawdata))
        #         print(res.header)
        #         assert not res.data
        #         # import pdb;pdb.set_trace()
        #     import pdb;pdb.set_trace()
        #     print("BYE")

