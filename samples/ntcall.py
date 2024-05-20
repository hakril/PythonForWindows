import windows
import windows.generated_def as gdef
import argparse

KNOWN_NTCALL = {}

def ntcall(f):
    assert f.__name__.startswith("do_")
    KNOWN_NTCALL[f.__name__[3:]] = f
    return f

def add_alias(f, name):
    KNOWN_NTCALL[name] = f
    return


def craft_root(root):
    if root == "currentdir":
        return current_dir()
    raw_root_arguments = root.split("!")
    root_arguments = parser.parse_args(raw_root_arguments)
    print("ROOT: {0}".format(root_arguments))
    root_handle = do_ntcall_from_args(root_arguments, subcall=True)
    print("Root handle is {0!r}".format(root_handle))
    return root_handle


def current_dir():
    print("Using <peb.ProcessParameters[0].CurrentDirectory.Handle> for root")
    return windows.current_process.peb.ProcessParameters[0].CurrentDirectory.Handle

def obj_attr_from_args(args):
    if args.translate:
        print("Translating DOSpath to NtPath")
        print(" * DOS: {0}".format(args.path))
        args.path = windows.utils.dospath_to_ntpath(args.path)
        print(" * NT : {0}".format(args.path))


    objattr = gdef.OBJECT_ATTRIBUTES.from_string(args.path)
    if args.root:
        objattr.RootDirectory = craft_root(args.root)
    if args.attributes:
        objattr.Attributes = args.attributes
    return objattr

@ntcall
def do_ntcreatefile(object_attributes):
    nh = gdef.HANDLE()
    access = gdef.MAXIMUM_ALLOWED
    ioblock = gdef.IO_STATUS_BLOCK()
    alloc_size = gdef.LARGE_INTEGER(0)
    attrib = gdef.FILE_ATTRIBUTE_NORMAL
    share = gdef.FILE_SHARE_READ
    disposition = gdef.FILE_OPEN
    options = 0
    eabuff = None
    easize = 0
    windows.winproxy.NtCreateFile(nh, access, object_attributes, ioblock, alloc_size, attrib, share, disposition, options, eabuff, easize)
    return nh.value

@ntcall
def do_ntopenfile(object_attributes):
    nh = gdef.HANDLE()
    access = gdef.MAXIMUM_ALLOWED
    ioblock = gdef.IO_STATUS_BLOCK()
    share = gdef.FILE_SHARE_READ
    options = 0
    windows.winproxy.NtOpenFile(nh, access, object_attributes, ioblock, share, options)
    return nh.value


@ntcall
def do_ntopenkey(object_attributes):
    nh = gdef.HANDLE()
    windows.winproxy.NtOpenKey(nh, gdef.MAXIMUM_ALLOWED, object_attributes)
    return nh.value

@ntcall
def do_ntcreatenamedpipefile(object_attributes):
    handle = gdef.HANDLE()
    access = gdef.GENERIC_READ | gdef.GENERIC_WRITE | gdef.SYNCHRONIZE
    ioblock = gdef.IO_STATUS_BLOCK()
    share = 3
    disposition = 0x2
    options = 0
    writemode = 1
    readmode = 1
    nonblock = 0
    MaxInstances = 0xffffffff
    InBufferSize = 0x1000
    OutBufferSize = 0x1000
    timeout = gdef.LARGE_INTEGER(0xffffffffb8797400)
    windows.winproxy.NtCreateNamedPipeFile(handle,access,object_attributes,ioblock,share,disposition,options,writemode,readmode,nonblock,MaxInstances,InBufferSize,OutBufferSize,timeout)
    return handle.value

@ntcall
def do_ntopendir(object_attributes):
    nh = gdef.HANDLE()
    windows.winproxy.NtOpenDirectoryObject(nh, gdef.MAXIMUM_ALLOWED, object_attributes)
    return nh.value


@ntcall
def do_ntcreatesection(object_attributes):
    nh  = gdef.HANDLE()
    access = gdef.MAXIMUM_ALLOWED
    size = gdef.LARGE_INTEGER(0x1000)
    prot = gdef.PAGE_READONLY
    alloc_attr = gdef.SEC_COMMIT
    windows.winproxy.NtCreateSection(nh, access, object_attributes, size, prot, alloc_attr, None)
    return nh.value

@ntcall
def do_ntopensection(object_attributes):
    nh  = gdef.HANDLE()
    access = gdef.MAXIMUM_ALLOWED
    windows.winproxy.NtOpenSection(nh, access, object_attributes)
    return nh.value

@ntcall
def do_ntopensymboliclinkobject(object_attributes):
    nh = gdef.HANDLE()
    access = gdef.MAXIMUM_ALLOWED
    windows.winproxy.NtOpenSymbolicLinkObject(nh, access , object_attributes)
    return nh.value

add_alias(do_ntopensymboliclinkobject, "opensymlink")

@ntcall
def do_ntcreatesymboliclinkobject(object_attributes):
    nh = gdef.HANDLE()
    access = gdef.MAXIMUM_ALLOWED
    # dest = gdef.UNICODE_STRING.from_string(r"\RPC Control\yolo_link") # Make a param
    dest = gdef.UNICODE_STRING.from_string(r"\Device\NamedPipe") # Make a param
    windows.winproxy.NtCreateSymbolicLinkObject(nh, access, object_attributes, dest)
    return nh.value


def do_ntcall_from_args(args, subcall=False):
    obj_attr = obj_attr_from_args(args)
    if not subcall:
        print("== Object Attribute ==")
    else:
        print("== Object Attribute (for root directory) ==")
    windows.utils.sprint(obj_attr, name="    objattr")
    func = KNOWN_NTCALL[args.function]
    try:
        handle = func(obj_attr)
    except WindowsError as e:
        print("== NtCall Error ==")
        print("    {0!r}".format(e))
        if subcall:
            raise
        return False
    print("== NtCall Success ==")
    print("    handle={0:#x}".format(handle))
    print("== Handle analysis ==")
    hinfo = [x for x in windows.current_process.handles if x.value == handle][0]
    print("   * Name: {0}".format(hinfo.name))
    print("   * Type: {0}".format(hinfo.type))
    print("   * Addr: {0:#x}".format(hinfo.pAddress))
    return handle


parser = argparse.ArgumentParser(prog=__file__)
parser.add_argument("function", choices=KNOWN_NTCALL)
parser.add_argument("path")
parser.add_argument("--root")
parser.add_argument("--attributes", type=int)
parser.add_argument("--translate", action="store_true", help="Translate <path> using <RtlDosPathNameToNtPathName_U>")


args = parser.parse_args()
do_ntcall_from_args(args)