import sys
import os.path
import pprint
import argparse
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.debug
import windows.generated_def as gdef

class FollowNtCreateFile(windows.debug.FunctionBP):
    TARGET = windows.winproxy.NtCreateFile

    def trigger(self, dbg, exc):
        params = self.extract_arguments(dbg.current_process, dbg.current_thread)
        filename = params["ObjectAttributes"].contents.ObjectName.contents.str
        handle_addr = params["FileHandle"].value
        self.data = (filename, handle_addr)
        self.break_on_ret(dbg, exc)

    def ret_trigger(self, dbg, exc):
        filename, handle_addr = self.data
        ret_value = dbg.current_thread.context.func_result # EAX / RAX depending of bitness
        if ret_value:
            return # Creation failed
        handle_value = dbg.current_process.read_ptr(handle_addr)
        return dbg.on_file_create(filename, handle_value)

class FollowReadFile(windows.debug.FunctionBP):
    TARGET = windows.winproxy.ReadFile

    def trigger(self, dbg, exc):
        params = self.extract_arguments(dbg.current_process, dbg.current_thread)
        self.data = params
        if params["hFile"] in dbg.followed_handles:
            self.break_on_ret(dbg, exc)

    def ret_trigger(self, dbg, exc):
        params = self.data
        ret_value = dbg.current_thread.context.func_result
        if not ret_value: # Read failed
            return
        buffer_size = dbg.current_process.read_dword(params["lpNumberOfBytesRead"])
        read_data = dbg.current_process.read_memory(params["lpBuffer"], buffer_size)
        return dbg.on_file_read(params["hFile"], read_data)

class FollowWriteFile(windows.debug.FunctionBP):
    TARGET = windows.winproxy.WriteFile

    def trigger(self, dbg, exc):
        params = self.extract_arguments(dbg.current_process, dbg.current_thread)
        write_data = dbg.current_process.read_memory(params["lpBuffer"], params["nNumberOfBytesToWrite"])
        return dbg.on_file_write(params["hFile"], write_data)

class FollowCloseFile(windows.debug.FunctionBP):
    TARGET = windows.winproxy.CloseHandle

    def trigger(self, dbg, exc):
        params = self.extract_arguments(dbg.current_process, dbg.current_thread)
        return dbg.on_file_close(params["hObject"])


class FileFollowDebugger(windows.debug.Debugger):
    def __init__(self, target, filenames):
        super(FileFollowDebugger, self).__init__(target)
        self.filenames = filenames
        self.followed_handles = {}
        self.add_bp(FollowNtCreateFile())
        self.add_bp(FollowReadFile())
        self.add_bp(FollowWriteFile())
        self.add_bp(FollowCloseFile())

    def on_exception(self, exc):
        if exc.ExceptionRecord.ExceptionCode == gdef.EXCEPTION_BREAKPOINT:
            return gdef.DBG_CONTINUE
        return gdef.DBG_EXCEPTION_NOT_HANDLED

    def on_file_create(self, filename, handle):
        if any(filename.lower().endswith(fname) for fname in self.filenames):
            self.followed_handles[handle] = filename
            print("Opened <{0}> as handle <{1:#x}>".format(filename, handle))


    def on_file_read(self, handle, data):
        filename = self.followed_handles[handle]
        print("Read from <{0}> ({1:#x})".format(filename, handle))
        print(repr(data))

    def on_file_write(self, handle, data):
        filename = self.followed_handles[handle]
        print("Write to <{0}> ({1:#x})".format(filename, handle))
        print(repr(data))

    def on_file_close(self, handle):
        try:
            filename = self.followed_handles[handle]
        except KeyError as e:
            return
        print("Closing handle <{0:#x}> to <{1}>".format(handle, filename))
        del self.followed_handles[handle]



if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog=__file__)
    parser.add_argument('exe')
    parser.add_argument('--cmdline', default="")
    parser.add_argument('files', nargs="+")
    args = parser.parse_args()
    print(args)

    target = windows.utils.create_process(args.exe, args.cmdline.split(), dwCreationFlags=gdef.DEBUG_PROCESS, show_windows=True)

    dbg = FileFollowDebugger(target, args.files)
    dbg.loop()
    print("BYE")


