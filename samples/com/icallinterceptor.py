import windows
import windows.generated_def as gdef
from windows import winproxy

# POC of ICallInterceptor
# Based on works by Pavel Yosifovich
# http://blogs.microsoft.co.il/pavely/2018/02/28/intercepting-com-objects-with-cogetinterceptor/

windows.com.init()

# Create an interceptor for the firewall (INetFwPolicy2)
interceptor = gdef.ICallInterceptor()
winproxy.CoGetInterceptor(gdef.INetFwPolicy2.IID, None, interceptor.IID, interceptor)

# The PythonForWindows firewall object is a real/valid INetFwPolicy2
# used for demos of ICallFrameEvents.Invoke
real_firewall = windows.system.network.firewall

# Custom Python ICallFrameEvents implementation
class MySink(windows.com.COMImplementation):
    IMPLEMENT = gdef.ICallFrameEvents

    def OnCall(self, this, frame):
        import pdb;pdb.set_trace()
        # this = gdef.ICallFrameEvents(this) # TODO: auto-translate this ?
        # frame = gdef.ICallFrame(frame)
        ifname = gdef.PWSTR()
        methodname = gdef.PWSTR()
        print("Hello from python sink !")
        frame.GetNames(ifname, methodname)
        print("Catching call to <{0}.{1}>".format(ifname.value, methodname.value))
        param0info = gdef.CALLFRAMEPARAMINFO()
        param0 = windows.com.ImprovedVariant()
        frame.GetParamInfo(0, param0info)
        frame.GetParam(0, param0)
        print("Info about parameters 0:")
        windows.utils.sprint(param0info, name=" * param0info")
        print("param0 value = {0}".format(param0.aslong))
        frame.Invoke(real_firewall)
        frame.SetReturnValue(1234)
        print("Leaving the sink !")
        return 0

# Create and register our ICallFrameEvents sink
xsink = MySink()
interceptor.RegisterSink(xsink)
# Create the INetFwPolicy2 interceptor interface
fakefirewall = gdef.INetFwPolicy2()
interceptor.QueryInterface(fakefirewall.IID, fakefirewall)

# Calling one of the INetFwPolicy2 function for testing
# Testing on https://msdn.microsoft.com/en-us/library/windows/desktop/aa365316(v=vs.85).aspx
enabled = gdef.VARIANT_BOOL()
res = fakefirewall.get_FirewallEnabled(2, enabled)
print("return value = {0}".format(res))
print("firewall enabled = {0}".format(enabled))

# Test a function taking a POINTER(ICallFrameEvents) (PTR to interface)
sink2 = gdef.ICallFrameEvents()
interceptor.GetRegisteredSink(sink2)
print(sink2, sink2.value)



# (cmd) python samples\com\icallinterceptor.py
# Hello from python sink !
# Catching call to <INetFwPolicy2.FirewallEnabled>
# Info about parameters 0:
#  * param0info.fIn -> 0x1
#  * param0info.fOut -> 0x0
#  * param0info.stackOffset -> 0x4L
#  * param0info.cbParam -> 0x4L
# param0 value = 2
# Leaving the sink !
# return value = 1234
# firewall enabled = VARIANT_BOOL(True)