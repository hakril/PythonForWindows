# -*- coding: utf-8 -*-

import windows
import windows.generated_def as gdef

from windows.pycompat import unicode_type


# Good test candidate for DeviceClass : System {4d36e97d-e325-11ce-bfc1-08002be10318}
# https://learn.microsoft.com/en-us/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors
# This class includes HALs, system buses, system bridges, the system ACPI driver, and the system volume manager driver.


def test_device_manager_class_name():
    assert u"System" in [c.name for c in windows.system.device_manager.classes]
    system_class = [c for c in windows.system.device_manager.classes if c.name == u"System"][0]
    assert isinstance(system_class.name, unicode_type)