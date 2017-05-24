import argparse
import os.path
import windows
import windows.generated_def as gdef

def find_processes_from_kwargs(pid=None, name=None, **kwargs):
    if pid is None and name is None:
        return windows.system.processes
    if pid is not None:
        return [p for p in windows.system.processes if p.pid == pid]
    return [p for p in windows.system.processes if p.name.lower() == name.lower()]

def find_one_process_from_kwargs(pid=None, name=None, **kwargs):
    if pid is not None:
        targets = [p for p in windows.system.processes if p.pid == pid]
        if not len(targets):
            raise ValueError("Could not find process with pid <{0}>".format(pid))
        assert len(targets) == 1
        return targets[0]

    targets =  [p for p in windows.system.processes if p.name.lower() == name.lower()]
    if not len(targets):
        raise ValueError("Could not find a process with name <{0}>".format(name))
    # Ask to choose a process
    if len(targets) == 1:
        return targets[0]
    print("Multiple process with name {0}, please choose:".format(name))
    for i, proc in enumerate(targets):
        print("  {0}) {1}".format(i, proc))
    choice = raw_input("Number > ")
    try:
        return targets[choice]
    except IndexError:
        raise


def proc_command_list(**kwargs):
    print("Listing processes")
    for proc in find_processes_from_kwargs(**kwargs):
        print (proc)

def proc_command_shell(**kwargs):
    target = find_one_process_from_kwargs(**kwargs)
    pfw_path = os.path.dirname(windows.__path__[0])
    print("Using PythonForWindows at <{0}>".format(pfw_path))
    try:
        target.execute_python("import sys; sys.path.append(r'{0}')".format(pfw_path))
        target.execute_python("import windows; windows.utils.pop_shell()")
    except Exception as e:
        print("Error while injecting python code: <{0!r}>".format(e))
        raise

def proc_command_kill(**kwargs):
    target = find_one_process_from_kwargs(**kwargs)
    print(target.exit(0))
    print(target)

def proc_command_killall(**kwargs):
    targets = find_processes_from_kwargs(**kwargs)
    for target in targets:
        target.exit(0)
        print(target)


PAGE_PROTECTIONS = [
gdef.PAGE_NOACCESS,
gdef.PAGE_READONLY,
gdef.PAGE_READWRITE,
gdef.PAGE_WRITECOPY,
gdef.PAGE_EXECUTE,
gdef.PAGE_EXECUTE_READ,
gdef.PAGE_EXECUTE_READWRITE,
gdef.PAGE_EXECUTE_WRITECOPY,
gdef.PAGE_GUARD,
gdef.PAGE_NOCACHE,
gdef.PAGE_WRITECOMBINE,
]
PAGE_PROTECTIONS_MAPPER = {x:x for x in PAGE_PROTECTIONS}

MEMORY_STATE = [gdef.MEM_COMMIT,
gdef.MEM_RESERVE,
gdef.MEM_DECOMMIT ,
gdef.MEM_RELEASE,
gdef.MEM_FREE,
gdef.MEM_PRIVATE,
gdef.MEM_MAPPED,
gdef.MEM_RESET,
gdef.MEM_TOP_DOWN ,
gdef.MEM_WRITE_WATCH,
gdef.MEM_PHYSICAL,
gdef.MEM_ROTATE,
gdef.MEM_LARGE_PAGES,
gdef.MEM_4MB_PAGES]
MEMORY_STATE_MAPPER = {x:x for x in MEMORY_STATE}

def proc_command_addr(**kwargs):
    target = find_one_process_from_kwargs(**kwargs)
    print(target)
    for addr in kwargs["addresses"]:
        print("== Address <{0:#x}> ==".format(addr, target))
        data = target.query_memory(addr)

        print("* BaseAddress = {0:#x}".format(data.BaseAddress))
        print("* RegionSize = {0:#x}".format(data.RegionSize))
        print("* State = {0}".format(MEMORY_STATE_MAPPER.get(data.RegionSize, data.RegionSize)))
        print("* Protect = {0}".format(PAGE_PROTECTIONS_MAPPER.get(data.Protect, data.Protect)))
        print('* MappedFile = "{0}"'.format(target.get_mapped_filename(addr)))

        x = work_set = target.query_working_setex([addr])
        attrs = x[0].VirtualAttributes
        if attrs.valid:
            print('* Shared = {0}'.format(bool(attrs.shared)))

        # Module
        for mod in target.peb.modules:
            if mod.baseaddr <= addr <  mod.baseaddr + mod.SizeOfImage:
                break
        else:
            print("Not in a module")
            return
        print("Part of {0}".format(mod))
        print("   * {0} + {1:#x}".format(mod.name, addr - mod.baseaddr))

        exports = mod.pe.exports
        res = (0xfffffff, "NOTFOUND")
        for name, exportaddr in exports.items():
            if isinstance(name, (int, long)):
                continue
            if exportaddr > addr:
                continue
            dist = addr - exportaddr
            res = min((dist, name), res)
            if dist == 0:
                break
        if res[1] != "NOTFOUND":
            print("   * {0}!{1}+{2:#x}".format(mod.name, res[1], dist))

# Services

def find_services_from_kwargs(name=None, **kwargs):
    if name is None:
        return windows.system.services
    return [p for p in windows.system.services if p.name.lower() == name.lower()]


def find_one_service_from_kwargs(name=None, **kwargs):
    targets =  [s for s in windows.system.services if s.name.lower() == name.lower()]
    if not len(targets):
        raise ValueError("Could not find a service with name <{0}>".format(name))
    # Ask to choose a process
    if len(targets) == 1:
        return targets[0]
    print("Multiple services with name {0}, please choose:".format(name))
    for i, serv in enumerate(targets):
        print("  {0}) {1}".format(i, serv))
    choice = raw_input("Number > ")
    try:
        return targets[choice]
    except IndexError:
        raise

def serv_command_list(**kwargs):
    print("Listing services")
    for serv in find_services_from_kwargs(**kwargs):
        print (serv)

def serv_command_start(**kwargs):
    serv = find_one_service_from_kwargs(**kwargs)
    serv.start()
    serv = find_one_service_from_kwargs(**kwargs)
    print(serv)

parser = argparse.ArgumentParser(prog=__file__)
subparsers = parser.add_subparsers(description='valid subcommands',)

# Processes commandes
proc_parser = subparsers.add_parser('proc')
proc_parser.set_defaults(func=proc_command_list)

group = proc_parser.add_mutually_exclusive_group()
group.add_argument('--pid', type=int, help='The pid of the process')
group.add_argument('--name', help='The name of the process')

proc_subparsers = proc_parser.add_subparsers(description='valid subcommands',)

proc_list_parser_ = proc_subparsers.add_parser('list')
proc_list_parser_.set_defaults(func=proc_command_list)

proc_inject_parser = proc_subparsers.add_parser('shell')
proc_inject_parser.set_defaults(func=proc_command_shell)

proc_inject_parser = proc_subparsers.add_parser('kill')
proc_inject_parser.set_defaults(func=proc_command_kill)

proc_inject_parser = proc_subparsers.add_parser('killall')
proc_inject_parser.set_defaults(func=proc_command_killall)

proc_addr_parser = proc_subparsers.add_parser('addr')
proc_addr_parser.set_defaults(func=proc_command_addr)
proc_addr_parser.add_argument('addresses', type=lambda x: int(x, 0), nargs="+", help='The addresses to explore')

# Services commandes
serv_parser = subparsers.add_parser('serv')
serv_parser.set_defaults(func=proc_command_list)

group = serv_parser.add_mutually_exclusive_group()
group.add_argument('--name', help='The name of the service')

serv_subparsers = serv_parser.add_subparsers(description='valid subcommands',)

serv_list_parser_ = serv_subparsers.add_parser('list')
serv_list_parser_.set_defaults(func=serv_command_list)

serv_list_parser_ = serv_subparsers.add_parser('start')
serv_list_parser_.set_defaults(func=serv_command_start)

if __name__ == "__main__":
    res = parser.parse_args()
    res.func(**res.__dict__)