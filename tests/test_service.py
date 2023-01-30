import pytest

import windows
import windows.generated_def as gdef


def test_services_process():
    services_with_process = [s for s in windows.system.services if s.status.dwProcessId]
    service = services_with_process[0]
    proc = service.process
    assert proc.pid == service.status.dwProcessId


def test_service_appinfo():
    appinfo = windows.system.services["Appinfo"]
    assert appinfo.status.type & gdef.SERVICE_WIN32_OWN_PROCESS
    # Check other fields
    assert appinfo.name == "Appinfo"
    assert appinfo.description == "Application Information"
    assert appinfo.security_descriptor


def test_service_start():
    faxservice = windows.system.services["Fax"]
    # Just start a random serivce with a string
    # Used to check string compat in py2/py3
    faxservice.start("TEST STRING")

