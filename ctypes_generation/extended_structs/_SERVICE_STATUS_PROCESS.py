class _SERVICE_STATUS_PROCESS(_SERVICE_STATUS_PROCESS):

    SERVICE_STATE = FlagMapper(SERVICE_STOPPED,
        SERVICE_START_PENDING,
        SERVICE_STOP_PENDING,
        SERVICE_RUNNING,
        SERVICE_CONTINUE_PENDING,
        SERVICE_PAUSE_PENDING,
        SERVICE_PAUSED)

    SERVICE_TYPE = FlagMapper(SERVICE_KERNEL_DRIVER,
        SERVICE_FILE_SYSTEM_DRIVER,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_WIN32_SHARE_PROCESS,
        SERVICE_INTERACTIVE_PROCESS)

    SERVICE_CONTROLE_ACCEPTED = FlagMapper()

    SERVICE_FLAGS = FlagMapper(SERVICE_RUNS_IN_SYSTEM_PROCESS)


    @property
    def dwCurrentState(self):
        return self.SERVICE_STATE[super(_SERVICE_STATUS_PROCESS, self).dwCurrentState]

    @property
    def dwServiceType(self):
        return self.SERVICE_TYPE[super(_SERVICE_STATUS_PROCESS, self).dwServiceType]

    @property
    def dwControlsAccepted(self):
        return self.SERVICE_CONTROLE_ACCEPTED[super(_SERVICE_STATUS_PROCESS, self).dwControlsAccepted]

    @property
    def dwServiceFlags(self):
        return self.SERVICE_FLAGS[super(_SERVICE_STATUS_PROCESS, self).dwServiceFlags]

    # Python friendly names
    state = dwCurrentState
    type = dwServiceType
    control_accepted = dwControlsAccepted
    flags = dwServiceFlags


    def __repr__(self):
        return """<{0} type={1!r} state={2!r}>""".format(type(self).__name__,
            self.type,
            self.state)