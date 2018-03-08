import windows
import windows.generated_def as gdef
from windows import winproxy

# POC of ICallInterceptor
# Based on works by Pavel Yosifovich
# http://blogs.microsoft.co.il/pavely/2018/02/28/intercepting-com-objects-with-cogetinterceptor/

# TODO: clean / comment

windows.com.init()

target = gdef.INetFwPolicy2

fakefirewall = gdef.INetFwPolicy2()

interceptor = gdef.ICallInterceptor()

winproxy.CoGetInterceptor(target.IID, None, interceptor.IID, interceptor)

real_firewall = windows.system.network.firewall

class MySink(windows.com.COMImplementation):
    IMPLEMENT = gdef.ICallFrameEvents

    def OnCall(self, this, frame):
        this = gdef.ICallFrameEvents(this) # TODO: auto-translate this ?
        frame = gdef.ICallFrame(frame)
        print(this)
        print(frame)
        name = gdef.PWSTR()
        name2 = gdef.PWSTR()
        frame.GetNames(name, name2)
        stack = frame.GetStackLocation()
        print(name)
        print(name2)
        x = gdef.CALLFRAMEPARAMINFO()
        ci = gdef.CALLFRAMEINFO()
        y = windows.com.ImprovedVariant()
        frame.GetParamInfo(1, x)
        frame.GetParam(1, y)
        frame.GetInfo(ci)
        windows.utils.sprint(x)
        # vbool = windows.current_process.read_dword(stack + 8)
        # You can use this to call the real function :)
        frame.Invoke(real_firewall)
        frame.SetReturnValue(1234)
        print("COM COM MON PYTHON :D")
        return 0

xsink = MySink()
interceptor.RegisterSink(xsink)
interceptor.QueryInterface(fakefirewall.IID, fakefirewall)

enabled = gdef.VARIANT_BOOL()
res = fakefirewall.get_FirewallEnabled(2, enabled)
print("return value = {0}".format(res))
print("enabled = {0}".format(enabled))