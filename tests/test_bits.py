import pytest
import os.path

import windows
import windows.generated_def as gdef

pytestmark = pytest.mark.usefixtures("init_com_security")

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))

@pytest.fixture
def bitsjob():
    newjob = windows.system.bits.create("PFW_TEST_BITSJOB", gdef.BG_JOB_TYPE_DOWNLOAD)
    yield newjob
    newjob.Cancel()

def test_job_state(bitsjob):
    # Check state returns the value and not enum struct
    assert bitsjob.state == gdef.BG_JOB_STATE_SUSPENDED
    # Enum value should be castable to int
    assert int(bitsjob.state) == gdef.BG_JOB_STATE_SUSPENDED

def test_job_multi_files(bitsjob):
    bitsjob.AddFile("https://example.com/REMOTE_FILE_1", os.path.join(SCRIPT_PATH, "local1"))
    bitsjob.AddFile("https://example.com/REMOTE_FILE_2", os.path.join(SCRIPT_PATH, "local2"))
    files = bitsjob.files
    assert len(files) == 2
