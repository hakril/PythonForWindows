import windows
import windows.generated_def as gdef

def test_ipv4_connection():
    windows.system.network.ipv4 # Better idea ?

def test_ipv6_connection():
    windows.system.network.ipv6 # Better idea ?

def test_firewall():
    firewall = windows.system.network.firewall
    assert firewall.enabled # Its a dict that should not be empty
    assert firewall.rules # Its a list that should not be empty
    # Just check that fields exists and do not crash for now
    rule = firewall.rules[0]
    rule.name
    rule.description
    rule.protocol
    rule.remote_port
    rule.local_port
    rule.local_address
    rule.remote_address
    rule.application_name
    rule.direction
    rule.enabled
