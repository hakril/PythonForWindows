import time
import windows


wmispace = windows.system.wmi["root\\cimv2"]
print("WMI namespace is <{0}>".format(wmispace))
proc_class = wmispace.get_object("Win32_process")
print("Process class is {0}".format(proc_class))

inparam_cls = proc_class.get_method("Create").inparam
print("Method Create InParams is <{0}>".format(inparam_cls))
print("Method Create InParams properties are <{0}>".format(inparam_cls.properties))
print("Creating instance of inparam")

inparam = inparam_cls()
print("InParam instance is <{0}>".format(inparam))
print("Setting <CommandLine>")
inparam["CommandLine"] = r"c:\windows\system32\notepad.exe"

print("Executing method")
# This API may change for something that better wraps cls/object/Parameters handling
outparam = wmispace.exec_method(proc_class, "Create", inparam)

print("OutParams is {0}".format(outparam))
print("Out params values are: {0}".format(outparam.properties))
target = windows.WinProcess(pid=int(outparam["ProcessId"]))
print("Created process is {0}".format(target))
print("Waiting 1s")
time.sleep(1)
print("Killing the process")
target.exit(0)



