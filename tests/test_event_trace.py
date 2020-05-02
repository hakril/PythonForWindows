import collections
import os

import windows
import windows.generated_def as gdef


TASK_SCHEDULER_PROVIDER = "047311A9-FA52-4A68-A1E4-4E289FBB8D17"

EVENT_ID_COUNT = collections.Counter()

def show(event):
    EVENT_ID_COUNT.update([event.id])


def test_etw_trace_open_with_guid():
    trace = windows.system.etw.open_trace("PFW_test_etw_1", guid="42424242-4242-4242-4242-000000001234")

def test_etw_trace_registration_and_processing():
    EVENT_ID_COUNT.clear()
    # RealTime Test
    trace = windows.system.etw.open_trace("PFW_test_etw_2", logfile="pfw_test_trace.etl")
    trace.start()
    trace.enable(TASK_SCHEDULER_PROVIDER, 0xff, 0xff)
    # Scheduler code that generate event
    windows.system.task_scheduler(r"\Microsoft\Windows\Chkdsk")["SyspartRepair"]
    # End of scheduler code
    trace.stop()
    trace.process(show)
    # Task scheduler generate event id 10,11,12
    assert EVENT_ID_COUNT[10] >= 1
    assert EVENT_ID_COUNT[11] >= 1
    assert EVENT_ID_COUNT[12] >= 1
    os.unlink("pfw_test_trace.etl")