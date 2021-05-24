import windows
import windows.pipe

def test_handle_process_id():
    handle_with_process = [h for h in windows.system.handles if h.dwProcessId]
    handle = handle_with_process[-1]
    proc = handle.process
    assert proc.pid == handle.dwProcessId == handle.pid


def test_local_handle_type():
    t = windows.current_process.threads[0]
    th = t.handle
    hobj = [h for h in windows.current_process.handles if h.value == th][0]
    assert hobj.type == "Thread"
    assert hobj.name == ""
    assert hobj.infos

PIPE_NAME = "PFW_Test_handle_Pipe"
TEST_FILE_FOR_HANDLE = r"C:\Windows\explorer.exe"

def test_remote_handle_type_and_name(proc32_64):
    # tmpfile
    proc32_64.execute_python("import windows; import windows.pipe")
    # A filename that a normal process should not have a handle on (to be sur)
    proc32_64.execute_python(r"""f = open(r"{filename}")""".format(filename=TEST_FILE_FOR_HANDLE))
    proc32_64.execute_python(r"""h = windows.utils.get_handle_from_file(f)""")
    with windows.pipe.create(PIPE_NAME) as np:
        proc32_64.execute_python("""windows.pipe.send_object("{pipe}", h)""".format(pipe=PIPE_NAME))
        file_handle_vlue = np.recv()
    remote_handle = [x for x in proc32_64.handles if x.value == file_handle_vlue][0]
    assert remote_handle.pid == proc32_64.pid
    assert remote_handle.type == "File"
    assert remote_handle.name.startswith("\Device\HarddiskVolume")
    assert remote_handle.name.endswith(TEST_FILE_FOR_HANDLE[2:]) # Remove volume letter
    assert remote_handle.infos