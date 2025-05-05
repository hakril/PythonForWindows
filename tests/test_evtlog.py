import pytest
import uuid

import windows
import gc

import windows.generated_def as gdef
import windows.winobject.event_log as evtl


CHANNEL_NAME = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
PUBLISHER_NAME = "Microsoft-Windows-Windows Firewall With Advanced Security"

SOME_FIREWALL_CHAN = ["Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
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

@pytest.mark.parametrize("channelname", [CHANNEL_NAME])
def test_event_channel_query(channelname):
    chan = windows.system.event_log[channelname]
    all_events = chan.events
    assert len(all_events) # Should have some event to test | skip else ?
    # Find an eventid that is present in the events
    target_evtid = all_events[0].id
    eventquery = chan.query(ids=target_evtid)
    assert isinstance(eventquery, evtl.EvtQuery)
    all_id_events = eventquery.all()
    assert len(all_id_events)
    assert len(all_id_events) <= len(all_events)
    assert all(evt.id == target_evtid for evt in all_id_events)
    # Extract event metadata
    event_data_names = chan.get_event_metadata(target_evtid).event_data
    # Check all event data match event metadata description
    for evt in all_id_events:
        # assert set(evt.data.keys()) == set(event_data_names)
        assert set(evt.data.keys()) == set(x["name"] for x in event_data_names)


@pytest.mark.parametrize("name, chans, eventid", [(PUBLISHER_NAME, SOME_FIREWALL_CHAN, 2004)])
def test_event_publisher(name, chans, eventid):
    publisher = windows.system.event_log[name]
    assert isinstance(publisher, evtl.EvtPublisher)
    assert publisher.name == name
    pmetadata = publisher.metadata
    # Pourquoi on a "System" dedans ?
    assert set(chan.name for chan in pmetadata.channels) >= set(chans)
    assert eventid in [evtmedata.id for evtmedata in pmetadata.events_metadata]

POWERSHELL_PATH = br"C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe"
POWERSHELL_ARG = [b"-NonInteractive]", b"PFW_TEST_STRING.NOTEXISTS"]

def test_new_event():
    chan = windows.system.event_log["Microsoft-Windows-PowerShell/Operational"]
    pre_events = chan.events
    p = windows.utils.create_process(POWERSHELL_PATH, POWERSHELL_ARG, show_windows=False)
    p.wait()
    import time; time.sleep(5) # It seems to take some time to log the event
    post_events = chan.events
    assert len(post_events) > len(pre_events)
    nb_new_events = len(post_events) - len(pre_events)
    new_events = post_events[-nb_new_events:]
    # Check that some new event were triggered by our powershell
    # TODO: should be nice to find simpler event log to trigger with controled data
    assert any(evt.pid == p.pid for evt in new_events)


def test_event_close():
    chan = windows.system.event_log["System"]
    start_usage = windows.current_process.memory_info.PrivateUsage
    count_max = 0x10000
    count = 0
    while count < count_max:
        for i,e  in enumerate(chan.query()):
            count += 1
    gc.collect()

    post_usage = windows.current_process.memory_info.PrivateUsage
    memory_usage_in_mo = (post_usage - start_usage) / 1024 / 1024
    memory_usage_in_ko = (post_usage - start_usage) / 1024
    # With auto-evtclose of evt there should not be too much memory used when
    # Variable are not accessible anymore
    assert memory_usage_in_mo <= 1

def test_evthandle_close():
    start_usage = windows.current_process.memory_info.PrivateUsage
    for i in range(0x2000):
        chan = windows.system.event_log["System"]
        query = chan.query()
        config = chan.config # Config is an EVT_HANDLE
        pubm = config.publisher.metadata
    gc.collect()

    post_usage = windows.current_process.memory_info.PrivateUsage
    memory_usage_in_mo = (post_usage - start_usage) / 1024 / 1024
    assert memory_usage_in_mo <= 1

def test_evtrender_evthandle_close():
    start_usage = windows.current_process.memory_info.PrivateUsage
    chan = windows.system.event_log["System"]
    query = chan.query()
    evt = next(query)
    for i in range(0x10000):
        x = evt.opcode
    gc.collect()

    post_usage = windows.current_process.memory_info.PrivateUsage
    memory_usage_in_mo = (post_usage - start_usage) / 1024 / 1024
    # Use ~20MO if render are leaking
    assert memory_usage_in_mo <= 1

tscheduler = windows.system.task_scheduler
troot = tscheduler.root

def generated_evt_log(id):
    uid = uuid.uuid4()
    task_name = "PFW_test_{0}_{1}".format(id, uid)
    new_task_definition = tscheduler.create()
    actions = new_task_definition.actions
    new_action = actions.create(gdef.TASK_ACTION_EXEC)
    new_action.path = r"c:\windows\system32\notepad.exe"
    new_task = troot.register(task_name, new_task_definition)
    task_path = new_task.path
    # Remove task immediatly, event was generated
    del troot[task_name]
    return task_path

TEST_TASK_EVENTLOG_CHANNEL = "Microsoft-Windows-TaskScheduler/Operational"
TEST_TASK_EVENTLOG_ID = 106 # Task registered

def test_evtlog_query_seek():
    chan = windows.system.event_log[TEST_TASK_EVENTLOG_CHANNEL]
    if not chan.config.enabled:
        pytest.skip("EvtLog channel <{0}> not enabled".format(TEST_TASK_EVENTLOG_CHANNEL))
    taskpath = generated_evt_log("query_seek")
    import time; time.sleep(5)
    query = chan.query(ids=TEST_TASK_EVENTLOG_ID)
    query.seek(-1)
    events = query.all()
    assert len(events) == 1
    assert events[0].data["TaskName"] == taskpath


@pytest.mark.parametrize("value", [
    12,
    "HELLO WORLD",
    b"BYTES HELLO WORLD",
])
def test_evtlog_improved_variant_from_value(value):
    assert evtl.ImprovedEVT_VARIANT.from_value(value)
