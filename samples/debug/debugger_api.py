import sys
import os.path
import pprint
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.test
import windows.debug

from windows.generated_def.winstructs import *

class MyDebugger(windows.debug.Debugger):
    def __init__(self, *args, **kwargs):
        super(MyDebugger, self).__init__(*args, **kwargs)
        self.struct_already_dump = set()

    def dump_struct_once(self, struct, name):
        if name in self.struct_already_dump:
            return
        windows.utils.print_ctypes_struct(struct, name, hexa=True)
        self.struct_already_dump.add(name)

    def on_exception(self, exception):
        print("<on_exception> called with {0}".format(exception))
        self.dump_struct_once(exception, "    exception")
        print("Single Stepping")
        return self.single_step()

    def on_single_step(self, exception):
        print("<on_single_step> called with {0}".format(exception))
        self.dump_struct_once(exception, "    single_step")

    def on_create_process(self, create_process):
        print("<on_create_process> called with {0}".format(create_process))
        self.dump_struct_once(create_process, "    create_process")
        pass

    def on_exit_process(self, exit_process):
        print("<on_exit_process> called with {0}".format(exit_process))
        self.dump_struct_once(exit_process, "    exit_process")
        pass

    def on_create_thread(self, create_thread):
        print("<on_create_thread> called with {0}".format(create_thread))
        self.dump_struct_once(create_thread, "    create_thread")
        pass

    def on_exit_thread(self, exit_thread):
        print("<on_exit_thread> called with {0}".format(exit_thread))
        self.dump_struct_once(exit_thread, "    exit_thread")
        pass

    def on_load_dll(self, load_dll):
        print("<on_load_dll> called with {0} ({1})".format(load_dll, self._get_loaded_dll(load_dll)))
        self.dump_struct_once(load_dll, "    load_dll")
        pass

    def on_unload_dll(self, unload_dll):
        print("<on_unload_dll> called with <{0}>".format(unload_dll))
        self.dump_struct_once(unload_dll, "    unload_dll")
        pass

    def on_output_debug_string(self, debug_string):
        print("<on_output_debug_string> called with {0}".format(debug_string))
        self.dump_struct_once(debug_string, "    debug_string")
        pass

    def on_rip(self, rip_info):
        print("<on_rip> called with {0}".format(rip_info))
        self.dump_struct_once(rip_info, "    rip_info")
        pass


calc = windows.test.pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
d = MyDebugger(calc)
d.loop()
