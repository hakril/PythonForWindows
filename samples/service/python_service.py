# A python script able to install itself as a service

import sys
import os.path
import argparse
import datetime
import ctypes

import windows
import windows.generated_def as gdef

SERVICE_NAME = u"PFW_SERVICE_DEMO"
SERVICE_DESCRIPTION = u"PythonForWindows demo service"

SERVICE_LOGFILE = os.path.join(os.path.dirname(__file__), "pfw_service_logs.txt")

SERVICE_HANDLE = None

def install_demo_service():
    path = "{executable} {pyfile} --run".format(executable=sys.executable, pyfile=__file__)
    print("Registering service <{0}> as : <{1}>".format(SERVICE_NAME, path))
    newservice = windows.system.services.create(
        name=SERVICE_NAME,
        description=SERVICE_DESCRIPTION,
        access=gdef.SERVICE_ALL_ACCESS,
        type=gdef.SERVICE_WIN32_OWN_PROCESS,
        start=gdef.SERVICE_DEMAND_START,
        path=path,
        user=None
    )
    print(newservice)
    return

def uninstall_demo_service():
    print("Deleting service")
    print(windows.system.services[SERVICE_NAME].delete())



def log(s):
    with open(SERVICE_LOGFILE, "a") as f:
        f.write("[{time}] {s}\n".format(time=datetime.datetime.now(), s=s))


@ctypes.WINFUNCTYPE(gdef.DWORD, gdef.DWORD, gdef.DWORD, gdef.PVOID, gdef.PVOID)
def service_handlerex(dwControl, dwEventType, lpEventData, lpContext):
    log("in service_handlerex")
    log("service_handlerex: called with {0}".format(dwControl))
    if dwControl == gdef.SERVICE_CONTROL_STOP:
        log("Stopping the service")
        running_status = gdef.SERVICE_STATUS(
            dwServiceSpecificExitCode=0,
            dwServiceType =gdef.SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState=gdef.SERVICE_STOPPED,
            dwWin32ExitCode=gdef.NO_ERROR,
            dwControlsAccepted=0
        )
        try:
            windows.winproxy.SetServiceStatus(SERVICE_HANDLE, running_status)
        except Exception as e:
            log(str(e))
    return 0

@ctypes.WINFUNCTYPE(gdef.PVOID, gdef.DWORD, ctypes.POINTER(gdef.LPWSTR))
def service_main(dwNumServicesArgs, lpServiceArgVectors):
    global SERVICE_HANDLE
    log("In service_main")
    log("service_main: {0}".format(dwNumServicesArgs))
    log("service_main: {0}".format(lpServiceArgVectors[0]))

    try:
        log("Calling RegisterServiceCtrlHandlerExW")
        SERVICE_HANDLE = windows.winproxy.RegisterServiceCtrlHandlerExW(SERVICE_NAME, ctypes.cast(service_handlerex, gdef.PVOID), None)
        log("RegisterServiceCtrlHandlerExW handle: {0}".format(SERVICE_HANDLE))

        running_status = gdef.SERVICE_STATUS(
            dwServiceSpecificExitCode=0,
            dwServiceType =gdef.SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState=gdef.SERVICE_RUNNING,
            dwWin32ExitCode=gdef.NO_ERROR,
            dwControlsAccepted=gdef.SERVICE_ACCEPT_STOP | gdef.SERVICE_ACCEPT_PAUSE_CONTINUE
        )
        res = windows.winproxy.SetServiceStatus(SERVICE_HANDLE, running_status)
        log("Service is running : {0}".format(res))
    except Exception as e:
        log(str(e))
        raise

    return None

def run_demo_service():
    log("start of run_demo_service()")
    try:
        SERVICE_TABLE = (gdef.SERVICE_TABLE_ENTRYW * 2)(
            gdef.SERVICE_TABLE_ENTRYW(SERVICE_NAME, ctypes.cast(service_main, gdef.PVOID)),
            gdef.SERVICE_TABLE_ENTRYW(None, None),
        )
        log("Calling: StartServiceCtrlDispatcherW()")
        result = windows.winproxy.StartServiceCtrlDispatcherW(SERVICE_TABLE)
        log("StartServiceCtrlDispatcherW returned: {0}".format(result))
        log("Quitting")
    except Exception as e:
        log(str(e))
        raise



parser = argparse.ArgumentParser(prog=__file__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--install",   action="store_true", help="Install the service in registry")
group.add_argument("--uninstall", action="store_true", help="UnInstall the service in registry")
group.add_argument("--run",     action="store_true", help="Called by the services.exe to run the service")


if __name__ == "__main__":
    args = parser.parse_args()
    if args.install:
        install_demo_service()
    elif args.uninstall:
        uninstall_demo_service()
    elif args.run:
        log("calling run_demo_service()")
        log(sys.argv)
        run_demo_service()
    else:
        raise ValueError("Unknown argument")