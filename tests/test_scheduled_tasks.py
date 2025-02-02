import pytest
import subprocess
import os.path

import windows
import windows.generated_def as gdef

SCHTASKS = r"c:\Windows\System32\schtasks.exe"

task_scheduler = windows.system.task_scheduler

def do_schtasks(*args):
    return subprocess.check_output([SCHTASKS] + list(args))

# /SC MONTHLY allows to create the task without admin privileges
def schtasks_create_task(taskname, binary, sc="MONTHLY"):
    return do_schtasks("/create", "/tn", taskname, "/tr", binary, "/sc",  sc)

def schtasks_delete_task(taskname):
    return do_schtasks("/delete", "/tn", taskname, "/f")

def schtasks_task_exists(taskname):
    try:
        return do_schtasks("/query", "/tn", taskname)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return False
        raise

SCHEDULED_TASK_PARAMS = [
    {"DIR": "", "NAME": "PFW_TEST1", "PATH": r'"c:\windows\system32\notepad.exe"', "ARGS": "PFW_TEST_PARAM.txt"},
    # Test in subdir
    {"DIR": "PFW_TEST_DIR", "NAME": "PFW_TEST1", "PATH": r'"c:\windows\system32\notepad.exe"', "ARGS": "PFW_TEST_PARAM.txt"}
]


@pytest.fixture(params=SCHEDULED_TASK_PARAMS)
def sheduled_task(request):
    descr = request.param
    fullpath = os.path.join(descr["DIR"], descr["NAME"])
    full_binary = "{0} {1}".format(descr["PATH"], descr["ARGS"])
    schtasks_create_task(fullpath, full_binary)
    yield descr
    schtasks_delete_task(fullpath)
    if descr["DIR"]:
        schtasks_delete_task(descr["DIR"])


def test_list_simple_task(sheduled_task):
    # taskdir = os.path.dirname(sheduled_task)
    # taskname = os.path.basename(sheduled_task)
    print(sheduled_task)
    if sheduled_task["DIR"]:
        tdir = windows.system.task_scheduler(sheduled_task["DIR"])
    else:
        tdir = windows.system.task_scheduler.root
    task = tdir[sheduled_task["NAME"]]
    assert task.name == sheduled_task["NAME"]
    triggers = task.definition.triggers
    assert len(list(triggers)) == 1
    assert triggers[1].type == gdef.TASK_TRIGGER_MONTHLY
    actions = task.definition.actions
    assert len(list(actions)) == 1
    assert actions[1].type == gdef.TASK_ACTION_EXEC
    assert actions[1].path == sheduled_task["PATH"]
    assert actions[1].arguments == sheduled_task["ARGS"]


@pytest.mark.parametrize("taskdict", SCHEDULED_TASK_PARAMS)
def test_create_delete_task(taskdict):
    tsched = tdir = windows.system.task_scheduler
    # Check task does not exists
    assert not schtasks_task_exists(os.path.join(taskdict["DIR"], taskdict["NAME"]))
    # Create Task
    if taskdict["DIR"]:
        tdir = windows.system.task_scheduler.root.create_folder(taskdict["DIR"])
    else:
        tdir = windows.system.task_scheduler.root
    ntd = tsched.create()
    actions = ntd.actions
    nea = actions.create(gdef.TASK_ACTION_EXEC)
    nea.path = taskdict["PATH"]
    nea.arguments = taskdict["ARGS"]
    tdir.register(taskdict["NAME"], ntd)
    # Check task presence
    assert schtasks_task_exists(os.path.join(taskdict["DIR"], taskdict["NAME"]))
    # Delete task
    del tdir[taskdict["NAME"]]
    if taskdict["DIR"]:
        tdir = windows.system.task_scheduler.root.delete_folder(taskdict["DIR"])

# Test COM tasks ?