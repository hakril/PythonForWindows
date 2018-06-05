import pytest

import windows
import windows.generated_def as gdef


def test_services_process():
    services_with_process = [s for s in windows.system.services if s.ServiceStatusProcess.dwProcessId]
    service = services_with_process[0]
    proc = service.process
    assert proc.pid == service.ServiceStatusProcess.dwProcessId


def test_service_appinfo():
    appinfos = [x for x in windows.system.services if x.name == "Appinfo"]
    assert len(appinfos) == 1
    appinfo = appinfos[0]
    assert appinfo.status.type & gdef.SERVICE_WIN32_OWN_PROCESS
    # Check other fields
    assert appinfo.name == "Appinfo"
    assert appinfo.description == "Application Information"