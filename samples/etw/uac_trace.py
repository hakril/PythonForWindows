import ctypes
import struct
import windows
import windows.generated_def as gdef
makeg = gdef.GUID.from_string

# This sample record the ETW event of provider CBB61B6D-A2CF-471A-9A58-A4CD5C08FFBA
# related to the UAC (service AppInfo)
# The ETW session is called MY_UAC_MONITOR

# Is then trigger the UAC and display the retrieved event afterward

def show(event):
    print("{0:#x}: {1}".format(event.EventHeader.TimeStamp, event))
    print("    guid: {0}".format(event.guid))
    print("    id: {0}".format(event.id))
    print("    opcode: {0}".format(event.opcode))
    print("    level: {0}".format(event.level))
    print("    data: {0!r}".format(event.user_data.replace("\x00", "")))
    return 0

session_name = "MY_UAC_MONITOR"
logfile_name = "uac.trace"

print("Recording UAC event in file <{0}> using session named <{1}>".format(logfile_name, session_name))

my_trace = windows.system.etw.open_trace(session_name, logfile=logfile_name)
my_trace.stop(soft=True) # Stop previous trace with this name if exists
my_trace.start()
my_trace.enable("CBB61B6D-A2CF-471A-9A58-A4CD5C08FFBA", 0xff, 0xff)

# Trigger UAC
windows.winproxy.ShellExecuteA(None, "runas", "mmc.exe", "BAD_MMC_FILENAME", None , 5)

my_trace.stop()
my_trace.process(show) #: Process the events registered in the trace (and logfile)