import threading

import windows
import windows.com
from  windows.generated_def.interfaces import (IBackgroundCopyManager, IEnumBackgroundCopyJobs, IBackgroundCopyJob,
                                                IBackgroundCopyCallback, COMImplementation, IUnknown, IBackgroundCopyError)
from windows.generated_def import DWORD, BG_JOB_TYPE_UPLOAD, BG_JOB_STATE_SUSPENDED, BG_ERROR_CONTEXT, HRESULT

BackgroundCopyManager = windows.com.IID.from_string("4991d34b-80a1-4291-83b6-3328366b9097")
BackgroundCopyManager1_5 = windows.com.IID.from_string("f087771f-d74f-4c1a-bb8a-e16aca9124ea")
BackgroundCopyManager2_0 = windows.com.IID.from_string("6d18ad12-bde3-4393-b311-099c346e6df9s")
BackgroundCopyManager2_5 = windows.com.IID.from_string("03ca98d6-ff5d-49b8-abc6-03dd84127020")
BackgroundCopyManager3_0 = windows.com.IID.from_string("659cdea7-489e-11d9-a9cd-000d56965251")


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
    @property
    def jobs(self):
        jobsenum  = IEnumBackgroundCopyJobs()
        self.EnumJobs(0, jobsenum)
        res = []
        nbretrieved = DWORD()
        while True:
            current = BitsCopyJob()
            jobsenum.Next(1, current, nbretrieved)
            if not nbretrieved.value:
                break
            res.append(current)
        return res

    def create(self, name, jobtype):
        myjob_uuid = windows.com.IID()
        newjob = BitsCopyJob()
        self.CreateJob(name, jobtype, myjob_uuid, newjob)
        return newjob

class BitsCopyJob(IBackgroundCopyJob):
    @property
    def iid(self):
        res = windows.com.IID()
        self.GetId(res)
        res.update_strid()
        return res

    @property
    def state(self):
        x = windows.generated_def.BG_JOB_STATE()
        self.GetState(x)
        return x

    def wait(self):
        if self.state.value == BG_JOB_STATE_SUSPENDED:
            raise ValueError("Cannot wait a BG_JOB_STATE_SUSPENDED job")
        event = threading.Event()
        callback_event = BitsCopyCallbackSetEvent(event)
        self.SetNotifyInterface(callback_event)
        self.SetNotifyFlags(1 | 2) # BG_NOTIFY_JOB_TRANSFERRED | BG_NOTIFY_JOB_ERROR
        event.wait()
        return True


    def __repr__(self):
        return '<{0} iid="{1}" at {2:#08x}>'.format(type(self).__name__, self.iid.to_string(), id(self))


class BitsCopyError(IBackgroundCopyError):
    @property
    def error(self):
        err_ctx = BG_ERROR_CONTEXT()
        err = HRESULT()
        self.GetError(err_ctx, err)
        return (err.value & 0xffffffff, err_ctx)