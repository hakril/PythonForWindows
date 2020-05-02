from collections import OrderedDict

import windows
from windows.generated_def.winstructs import *
from windows.generated_def import windef
from windows.winobject.process import WinProcess, WinThread
from windows.pycompat import basestring


STANDARD_BP = "BP"
HARDWARE_EXEC_BP = "HXBP"
MEMORY_BREAKPOINT = "MEMBP"

class Breakpoint(object):
    """An standard (Int3) breakpoint (type == ``STANDARD_BP``)"""
    type = STANDARD_BP # REAL BP
    def __init__(self, addr):
        self.addr = addr

    def apply_to_target(self, target):
        return isinstance(target, WinProcess)

    def trigger(self, dbg, exception):
        """Called when breakpoint is hit"""
        pass


class ProxyBreakpoint(Breakpoint):
    def __init__(self, target, addr, type):
        self.target = target
        self.addr = addr
        self.type = type

    def trigger(self, dbg, exception):
        return self.target(dbg, exception)


class HXBreakpoint(Breakpoint):
    """An hardware-execution breakpoint (type == ``HARDWARE_EXEC_BP``)"""
    type = HARDWARE_EXEC_BP

    def apply_to_target(self, target):
        return isinstance(target, WinThread)

class MemoryBreakpoint(Breakpoint):
    """A memory breakpoint (type == ``MEMORY_BREAKPOINT``)"""
    type = MEMORY_BREAKPOINT
    DEFAULT_EVENTS = "RWX"
    DEFAULT_SIZE = 0x1000
    def __init__(self, addr, size=None, events=None):
        """``size``: the size of the memory breakpoint.

        ``events``: a string representing the events that interest the BP (any of "RWX")"""
        super(MemoryBreakpoint, self).__init__(addr)
        self.size = size if size is not None else self.DEFAULT_SIZE
        events = events if events is not None else self.DEFAULT_EVENTS
        self.events = set(events)

    def trigger(self, dbg, exception):
        """Called when breakpoint is hit"""
        pass


## Arguments Helper (need to move this elsewhere)
class X86ArgumentRetriever(object):
    def get_arg(self, nb, proc, thread):
        return proc.read_dword(thread.context.sp + 4 + (4 * nb))

    def set_arg(self, nb, value, proc, thread):
        return proc.write_dword(thread.context.sp + 4 + (4 * nb), value)

class X64ArgumentRetriever(object):
    REG_ARGS = ["Rcx", "Rdx", "R8", "R9"]
    def get_arg(self, nb, proc, thread):
        if nb < len(self.REG_ARGS):
            return getattr(thread.context, self.REG_ARGS[nb])
        return proc.read_qword(thread.context.sp + 8 + (8 * nb))

    def set_arg(self, nb, value, proc, thread):
        if nb < len(self.REG_ARGS):
            ctx = thread.context
            setattr(ctx, self.REG_ARGS[nb], value)
            return thread.set_context(ctx)
        return proc.write_qword(thread.context.sp + 8 + (8 * nb), value)

## Behaviour breakpoint !
# class FunctionParamDumpBP(Breakpoint):
class FunctionParamDumpBPAbstract(object):
    def __init__(self, addr=None, target=None):
        if target is None:
            try:
                target = self.TARGET
            except AttributeError as e:
                raise ValueError("{0} bp without a <target> must have a <TARGET> class attribute")
        if addr is None:
            addr = "{0}!{1}".format(target.target_dll, target.target_func)
        super(FunctionParamDumpBPAbstract, self).__init__(addr)
        self.target = target
        self.target_args = target.prototype._argtypes_
        self.target_params = target.params

    def extract_arguments_32bits(self, cproc, cthread):
        x = windows.debug.X86ArgumentRetriever()
        res = OrderedDict()
        for i, (name, type) in enumerate(zip(self.target_params, self.target_args)):
            value = x.get_arg(i, cproc, cthread)
            rt = windows.remotectypes.transform_type_to_remote32bits(type)
            if issubclass(rt, windows.remotectypes.RemoteValue):
                t = rt(value, cproc)
            else:
                t = rt(value)
            # Will fail in py3..
            content = None
            try:
                content = t.contents
            except Exception as e:
                # contents will fail on basic type
                # Not really an expected behavior
                # But it works for now.. (and since a while)
                pass
            if content is None:
                t = t.value
            res[name[1]] = t
        return res

    def extract_arguments_64bits(self, cproc, cthread):
        x = windows.debug.X64ArgumentRetriever()
        res = OrderedDict()
        for i, (name, type) in enumerate(zip(self.target_params, self.target_args)):
            value = x.get_arg(i, cproc, cthread)
            rt = windows.remotectypes.transform_type_to_remote64bits(type)
            if issubclass(rt, windows.remotectypes.RemoteValue):
                t = rt(value, cproc)
            else:
                t = rt(value)
            if not hasattr(t, "contents"):
                try:
                    t = t.value
                except AttributeError:
                    pass
            res[name[1]] = t
        return res

    def extract_arguments(self, cproc, cthread):
        """Extracts the functions parameters in an :class:`OrderedDict`"""
        if windows.current_process.bitness == 32:
            return self.extract_arguments_32bits(cproc, cthread)
        if cproc.bitness == 64:
            return self.extract_arguments_64bits(cproc, cthread)
        # SysWow process from a 64bits debugger, handle bitness with CS
        if cthread.context.SegCs == windows.syswow64.CS_32bits:
            return self.extract_arguments_32bits(cproc, cthread)
        return self.extract_arguments_64bits(cproc, cthread)

    def arguments(self, dbg):
        "TEST PARAM DICT"
        if windows.current_process.bitness == 32:
            extractor = windows.debug.X86ArgumentRetriever()
        elif dbg.current_process.bitness == 64:
            extractor = windows.debug.X64ArgumentRetriever()
        elif dbg.current_thread.context.SegCs == windows.syswow64.CS_32bits:
            extractor = windows.debug.X86ArgumentRetriever()
        else:
            extractor = windows.debug.X64ArgumentRetriever()
        name_map = {name:i for i, name in enumerate(t[1] for t in self.target_params)}
        return FunctionParameterProxy(extractor, name_map, self.target_args, dbg)

class FunctionParameterProxy(object):
    # TODO: clean this + put more of the logic in the X64ArgumentRetriever
    def __init__(self, extractor, name_map, parameters_type, x):
        self.extractor = extractor
        self.name_map = name_map
        self.parameters_type = parameters_type
        self.x = x

    def __getitem__(self, x):
        if isinstance(x, basestring):
            x = self.name_map[x]
        # import pdb;pdb.set_trace()
        argtype = self.parameters_type[x]
        value = self.extractor.get_arg(x, self.x.current_process, self.x.current_thread)
        rt = windows.remotectypes.transform_type_to_remote32bits(argtype)
        if issubclass(rt, windows.remotectypes.RemoteValue):
            t = rt(value, self.x.current_process)
        else:
            t = rt(value)
        if not hasattr(t, "contents"):
            try:
                t = t.value
            except AttributeError:
                pass
        return t

    def __setitem__(self, x, value):
        if isinstance(x, basestring):
            x = self.name_map[x]
        try:
            ctypes.cast(value, PVOID)
        except ctypes.ArgumentError:
            pass
        value = getattr(value, "value", value)
        return self.extractor.set_arg(x, value, self.x.current_process, self.x.current_thread)



class FunctionParamDumpBP(FunctionParamDumpBPAbstract, Breakpoint):
    pass

class FunctionParamDumpHXBP(FunctionParamDumpBPAbstract, HXBreakpoint):
    pass

class FunctionRetBP(Breakpoint):
    def __init__(self, addr, initial_breakpoint):
        super(FunctionRetBP, self).__init__(addr)
        self.initial_breakpoint = initial_breakpoint

    def trigger(self, dbg, exc):
        dbg.del_bp(self, targets=[dbg.current_process])
        return self.initial_breakpoint.ret_trigger(dbg, exc)


class FunctionCallBP(Breakpoint):
    """A Breakpoint that allow to trigger at the return of a function"""
    def break_on_ret(self, dbg, exception):
        """Setup a breakpoint at the return address of the function, this breakpoint will call :func:`ret_trigger`"""
        return_addr = self.get_ret_addr(dbg, exception)
        dbg.add_bp(FunctionRetBP(return_addr, self), target=dbg.current_process)

    def get_ret_addr(self, dbg, exception):
        """Get the return address of the current target, only valid in the trigger() function."""
        cproc = dbg.current_process
        return dbg.current_process.read_ptr(dbg.current_thread.context.sp)


    def ret_trigger(self, dbg, exception):
        """Called at the return of the function if :func:`break_on_ret` was called"""
        raise NotImplementedError("ret_trigger")


class FunctionBP(FunctionCallBP, FunctionParamDumpBP):
    """A breakpoint that accepts a function from :mod:`windows.winproxy` and able to:

        - Extract the arguments of the functions
        - Break at the return of the function
    """

class PrintBP(Breakpoint):
    def __init__(self, addr, format, func=None):
        super(PrintBP, self).__init__(addr)
        self.format = format
        self.func = func

    def trigger(self, dbg, exc):
        thread = dbg.current_thread
        format_dict = {"dbg": dbg, "exc": exc, "proc": dbg.current_process, "thread": thread, "ctx": thread.context}
        if self.func:
            format_dict.update(self.func(**format_dict))
        print(self.format.format(**format_dict))