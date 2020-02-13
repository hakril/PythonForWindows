import pytest

import windows
import windows.generated_def as gdef


def test_services_process():
    services_with_process = [s for s in windows.system.services if s.status.dwProcessId]
    service = services_with_process[0]
    proc = service.process
    assert proc.pid == service.status.dwProcessId


def test_service_appinfo():
    appinfos = [x for x in windows.system.services if x.name == b"Appinfo"]
    assert len(appinfos) == 1
    appinfo = appinfos[0]
    assert appinfo.status.type & gdef.SERVICE_WIN32_OWN_PROCESS
    # Check other fields
    assert appinfo.name == b"Appinfo"
    assert appinfo.description == b"Application Information"