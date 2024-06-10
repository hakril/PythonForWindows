import windows
import windows.generated_def as gdef

print("Listing the first 3 services:")
for service in windows.system.services[:3]:
    print(" * {0}".format(service))
print("")

TARGET_SERVICE = "TapiSrv"
print("Retriving service <{0}>".format(TARGET_SERVICE))
service = windows.system.services[TARGET_SERVICE]
print("{0}".format(service))
print(" - name: {0!r}".format(service.name))
print(" - description: {0!r}".format(service.description))
print(" - state: {0!r}".format(service.status.state))
print(" - type: {0!r}".format(service.status.type))
print(" - process: {0!r}".format(service.process))
print(" - security-description: {0}".format(service.security_descriptor))

if service.status.state == gdef.SERVICE_RUNNING:
    print("Service already running, not trying to start it")
else:
    print("Trying to start the service")
    service.start()
    while service.status.state != gdef.SERVICE_RUNNING:
        pass
    print("Service started !")
    print("{0}".format(service))
    print(" - state: {0!r}".format(service.status.state))
    print(" - process: {0!r}".format(service.process))