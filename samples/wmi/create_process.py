import windows
import windows.com
import windows.generated_def as gdef

def bstr_variant(s):
    v = windows.com.Variant()
    v.vt = gdef.VT_BSTR
    v._VARIANT_NAME_3.bstrVal = s
    return v


wmireq = windows.system.wmi["root\\cimv2"]
proc_class = wmireq.get_object("Win32_process")

# # Method 1
inparam = proc_class.get_method("Create").inparam.spawn_instance()
inparam["CommandLine"] = r"c:\windows\system32\notepad.exe trolol.exe"
# Create a test checking return value
xx = wmireq.exec_method(proc_class, "Create", inparam)
print(xx)
print(xx.as_dict())

## Method2

# class MyResult(gdef.IWbemCallResult):
    # def result(self):
        # res = type(proc_class)()
        # self.GetResultObject(gdef.WBEM_INFINITE, res)
        # return res


# proc = proc_class.spawn()
# cmdline = bstr_variant(r"c:\windows\system32\notepad.exe")
# proc.put_variant("CommandLine", cmdline)
# res = wmireq.put_instance(proc)

