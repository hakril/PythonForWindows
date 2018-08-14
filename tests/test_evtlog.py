import pytest

import windows
import windows.generated_def as gdef

import windows.winobject.event_log as evtl


CHANNEL_NAME = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
PUBLISHER_NAME = "Microsoft-Windows-Windows Firewall With Advanced Security"

ALL_FIREWALL_CHAN = ["Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        "Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity",
        "Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose",
        "Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurityVerbose",
        "Network Isolation Operational"]


@pytest.mark.parametrize("name, publisher_name", [(CHANNEL_NAME, PUBLISHER_NAME)])
def test_event_channel(name, publisher_name):
    chan = windows.system.event_log[name]
    assert isinstance(chan, evtl.EvtChannel)
    assert chan.name == name
    assert chan.config.publisher.name == publisher_name
    assert not chan.config.classic

@pytest.mark.parametrize("name, eventid", [(CHANNEL_NAME, 2004)])
def test_event_channel_query(name, eventid):
    chan = windows.system.event_log[name]
    all_events = chan.events
    assert len(all_events) # Should have some event to test | skip else ?
    eventquery = chan.query(ids=2004)
    assert isinstance(eventquery, evtl.EvtQuery)
    all_id_events = eventquery.all()
    assert len(all_id_events)
    assert len(all_id_events) <= len(all_events)
    assert all(evt.id == eventid for evt in all_id_events)
    # Extract event metadata
    event_data_names = chan.get_event_metadata(eventid).event_data
    # Check all event data match event metadata description
    for evt in all_id_events:
        assert set(evt.data.keys()) == set(event_data_names)


@pytest.mark.parametrize("name, chans, eventid", [(PUBLISHER_NAME, ALL_FIREWALL_CHAN, 2004)])
def test_event_publisher(name, chans, eventid):
    publisher = windows.system.event_log[name]
    assert isinstance(publisher, evtl.EvtPublisher)
    assert publisher.name == name
    pmetadata = publisher.metadata
    assert set(chan.name for chan in pmetadata.channels) == set(chans)
    assert eventid in [evtmedata.id for evtmedata in pmetadata.events_metadata]

POWERSHELL_PATH = r"C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe"
POWERSHELL_ARG = "PFW_TEST_STRING.NOTEXISTS"

def test_new_event():
    chan = windows.system.event_log["Microsoft-Windows-PowerShell/Operational"]
    pre_events = chan.events
    p = windows.utils.create_process(POWERSHELL_PATH, ["PFW_TEST_STRING.NOTEXISTS"], show_windows=False)
    p.wait()
    import time; time.sleep(1) # It seems to take some time to log the event
    post_events = chan.events
    assert len(post_events) > len(pre_events)
    nb_new_events = len(post_events) - len(pre_events)
    new_events = post_events[-nb_new_events:]
    # Check that some new event were triggered by our powershell
    # TODO: should be nice to find simpler event log to trigger with controled data
    assert any(evt.pid == p.pid for evt in new_events)



