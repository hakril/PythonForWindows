import threading

import windows
import windows.com
from windows.com import COMImplementation
from  windows.generated_def.interfaces import (IBackgroundCopyManager, IEnumBackgroundCopyJobs, IBackgroundCopyJob,
                                                IBackgroundCopyCallback, IUnknown, IBackgroundCopyError, IEnumBackgroundCopyFiles,
                                                IBackgroundCopyFile)
import windows.generated_def as gdef

BackgroundCopyManager = windows.com.IID.from_string("4991d34b-80a1-4291-83b6-3328366b9097")
BackgroundCopyManager1_5 = windows.com.IID.from_string("f087771f-d74f-4c1a-bb8a-e16aca9124ea")
BackgroundCopyManager2_0 = windows.com.IID.from_string("6d18ad12-bde3-4393-b311-099c346e6df9s")
BackgroundCopyManager2_5 = windows.com.IID.from_string("03ca98d6-ff5d-49b8-abc6-03dd84127020")
BackgroundCopyManager3_0 = windows.com.IID.from_string("659cdea7-489e-11d9-a9cd-000d56965251")

BITS_CLS_BY_VERSION = {
    (1,0): BackgroundCopyManager,
    (1,5): BackgroundCopyManager1_5,
    (2,0): BackgroundCopyManager2_0,
    (2,5): BackgroundCopyManager2_5,
    (3,0): BackgroundCopyManager3_0,
}


class BitsCopyCallback(COMImplementation):
    IMPLEMENT = IBackgroundCopyCallback

    def JobError(self, this, job, error):
        return True

    def JobTransferred(self, this, job):
        #copy_terminated.set()
        return True

    def JobModification(self, job, reserved):
        return True

class BitsCopyCallbackSetEvent(BitsCopyCallback):
    def __init__(self, event):
        super(BitsCopyCallbackSetEvent, self).__init__()
        self.event = event

    # With the current generated_def.interface design, the current
    # prototype is:
    #     ctypes.WINFUNCTYPE(HRESULT, PVOID, PVOID)(4, "JobError")
    # How should I address that ?
    def JobError(self, this, job, error):
        job = BitsCopyJob(job)
        error = BitsCopyError(error)
        errcode, errctx = error.error
        print("Copy failed with error code <{0:#x}> (ctx={1})".format(errcode, errctx))
        print("see <https://msdn.microsoft.com/en-us/library/windows/desktop/aa362823(v=vs.85).aspx>")
        self.event.set()
        return True

    def JobTransferred(self, this, job):
        self.event.set()
        return True

class BitsCopyManager(IBackgroundCopyManager):
    def get_jobs(self, flags=0):
        jobsenum  = IEnumBackgroundCopyJobs()
        self.EnumJobs(flags, jobsenum)
        res = []
        nbretrieved = gdef.DWORD()
        while True:
            current = BitsCopyJob()
            jobsenum.Next(1, current, nbretrieved)
            if not nbretrieved.value:
                break
            res.append(current.promote())
        jobsenum.Release()
        return res

    @property
    def jobs(self):
        return self.get_jobs()

    def create(self, name, jobtype):
        myjob_uuid = windows.com.IID()
        newjob = BitsCopyJob()
        self.CreateJob(name, jobtype, myjob_uuid, newjob)
        return newjob.promote()

class BitsCopyJob(IBackgroundCopyJob):
    version = 1
    @property
    def owner(self):
        owner = gdef.LPWSTR()
        self.GetOwner(owner)
        data = owner.value
        windows.winproxy.CoTaskMemFree(owner)
        return data


    @property
    def iid(self):
        res = windows.com.IID()
        self.GetId(res)
        res.update_strid()
        return res

    @property
    def state(self):
        x = gdef.BG_JOB_STATE()
        self.GetState(x)
        return x.value

    @property
    def name(self):
        descr = gdef.LPWSTR()
        self.GetDisplayName(descr)
        data = descr.value
        windows.winproxy.CoTaskMemFree(descr)
        return data

    @property
    def description(self):
        descr = gdef.LPWSTR()
        self.GetDescription(descr)
        data = descr.value
        windows.winproxy.CoTaskMemFree(descr)
        return data

    @property
    def files(self):
        enum = IEnumBackgroundCopyFiles()
        self.EnumFiles(enum)
        count = gdef.ULONG()
        enum.GetCount(count)
        if not count:
            return []
        res_size = gdef.ULONG()
        array =  (BitsFile * count.value)()
        enum.Next(count.value, array, res_size)
        return array[:res_size.value]

    @property
    def type(self):
        res = gdef.BG_JOB_TYPE()
        self.GetType(res)
        return res.value

    @property
    def priority(self):
        priority = gdef.BG_JOB_PRIORITY()
        self.GetPriority(priority)
        return priority.value

    @property
    def minimum_retry_delay(self):
        retry_delay = gdef.ULONG()
        self.GetMinimumRetryDelay(retry_delay)
        return retry_delay.value

    @property
    def proxy_settings(self):
        ProxyUsage = gdef.BG_JOB_PROXY_USAGE()
        ProxyList = gdef.LPWSTR()
        ProxyBypassList = gdef.LPWSTR()
        self.GetProxySettings(ProxyUsage, ProxyList, ProxyBypassList)
        result = ProxyUsage.value, ProxyList.value, ProxyBypassList.value
        windows.winproxy.CoTaskMemFree(ProxyList)
        windows.winproxy.CoTaskMemFree(ProxyBypassList)
        return result

    @property
    def times(self):
        res = gdef.BG_JOB_TIMES()
        self.GetTimes(res)
        return res


    def wait(self):
        if self.state.value == gdef.BG_JOB_STATE_SUSPENDED:
            raise ValueError("Cannot wait a BG_JOB_STATE_SUSPENDED job")
        event = threading.Event()
        callback_event = BitsCopyCallbackSetEvent(event)
        self.SetNotifyInterface(callback_event)
        self.SetNotifyFlags(1 | 2) # BG_NOTIFY_JOB_TRANSFERRED | BG_NOTIFY_JOB_ERROR
        event.wait()
        return True


    def promote(self):
        try:
            return self.query(BitsCopyJob2)
        except WindowsError as e:
            return self


    def __repr__(self):
        return '<{0} iid="{1}" at {2:#08x}>'.format(type(self).__name__, self.iid, id(self))


class BitsCopyJob2(gdef.IBackgroundCopyJob2, BitsCopyJob):
    version = 2
    @property
    def notify_cmdline(self):
        path = gdef.LPWSTR()
        params = gdef.LPWSTR()
        self.GetNotifyCmdLine(path, params)
        strpath, strparams = path.value, params.value
        windows.winproxy.CoTaskMemFree(path)
        windows.winproxy.CoTaskMemFree(params)
        return strpath, strparams


class BitsFile(IBackgroundCopyFile):
    version = 1
    @property
    def local_name(self):
        name = gdef.LPWSTR()
        self.GetLocalName(name)
        data = name.value
        windows.winproxy.CoTaskMemFree(name)
        return data

    @property
    def remote_name(self):
        name = gdef.LPWSTR()
        self.GetRemoteName(name)
        data = name.value
        windows.winproxy.CoTaskMemFree(name)
        return data

    @property
    def progress(self):
        progress = gdef.BG_FILE_PROGRESS()
        self.GetProgress(progress)
        return progress

    def promote(self):
        try:
            return self.query(BitsFile3)
        except WindowsError as e:
            return self

class BitsFile3(gdef.IBackgroundCopyFile3, BitsFile):
    version = 3
    @property
    def temporary_name(self):
        name = gdef.LPWSTR()
        self.GetTemporaryName(name)
        data = name.value
        windows.winproxy.CoTaskMemFree(name)
        return data

class BitsCopyError(IBackgroundCopyError):
    @property
    def error(self):
        err_ctx = gdef.BG_ERROR_CONTEXT()
        err = gdef.HRESULT()
        self.GetError(err_ctx, err)
        return (err.value & 0xffffffff, err_ctx)


def create_manager(version=(3,0)):
    windows.com.init()
    clsid = BITS_CLS_BY_VERSION[version]
    manager = BitsCopyManager()
    windows.com.create_instance(clsid, manager)
    return manager