.. module:: windows.generated_def.interfaces

Interfaces
----------
.. class:: ICallFrame

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetInfo
    .. method:: GetIIDAndMethod
    .. method:: GetNames
    .. method:: GetStackLocation
    .. method:: SetStackLocation
    .. method:: SetReturnValue
    .. method:: GetReturnValue
    .. method:: GetParamInfo
    .. method:: SetParam
    .. method:: GetParam
    .. method:: Copy
    .. method:: Free
    .. method:: FreeParam
    .. method:: WalkFrame
    .. method:: GetMarshalSizeMax
    .. method:: Marshal
    .. method:: Unmarshal
    .. method:: ReleaseMarshalData
    .. method:: Invoke


.. class:: ICallFrameEvents

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: OnCall


.. class:: ICallFrameWalker

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: OnWalkInterface


.. class:: ICallInterceptor

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: CallIndirect
    .. method:: GetMethodInfo
    .. method:: GetStackSize
    .. method:: GetIID
    .. method:: RegisterSink
    .. method:: GetRegisteredSink


.. class:: IDispatch

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke


.. class:: IEnumVARIANT

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Next
    .. method:: Skip
    .. method:: Reset
    .. method:: Clone


.. class:: INetFwPolicy2

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_CurrentProfileTypes
    .. method:: get_FirewallEnabled
    .. method:: put_FirewallEnabled
    .. method:: get_ExcludedInterfaces
    .. method:: put_ExcludedInterfaces
    .. method:: get_BlockAllInboundTraffic
    .. method:: put_BlockAllInboundTraffic
    .. method:: get_NotificationsDisabled
    .. method:: put_NotificationsDisabled
    .. method:: get_UnicastResponsesToMulticastBroadcastDisabled
    .. method:: put_UnicastResponsesToMulticastBroadcastDisabled
    .. method:: get_Rules
    .. method:: get_ServiceRestriction
    .. method:: EnableRuleGroup
    .. method:: IsRuleGroupEnabled
    .. method:: RestoreLocalFirewallDefaults
    .. method:: get_DefaultInboundAction
    .. method:: put_DefaultInboundAction
    .. method:: get_DefaultOutboundAction
    .. method:: put_DefaultOutboundAction
    .. method:: get_IsRuleGroupCurrentlyEnabled
    .. method:: get_LocalPolicyModifyState


.. class:: INetFwRules

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Count
    .. method:: Add
    .. method:: Remove
    .. method:: Item
    .. method:: get__NewEnum


.. class:: INetFwRule

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Name
    .. method:: put_Name
    .. method:: get_Description
    .. method:: put_Description
    .. method:: get_ApplicationName
    .. method:: put_ApplicationName
    .. method:: get_ServiceName
    .. method:: put_ServiceName
    .. method:: get_Protocol
    .. method:: put_Protocol
    .. method:: get_LocalPorts
    .. method:: put_LocalPorts
    .. method:: get_RemotePorts
    .. method:: put_RemotePorts
    .. method:: get_LocalAddresses
    .. method:: put_LocalAddresses
    .. method:: get_RemoteAddresses
    .. method:: put_RemoteAddresses
    .. method:: get_IcmpTypesAndCodes
    .. method:: put_IcmpTypesAndCodes
    .. method:: get_Direction
    .. method:: put_Direction
    .. method:: get_Interfaces
    .. method:: put_Interfaces
    .. method:: get_InterfaceTypes
    .. method:: put_InterfaceTypes
    .. method:: get_Enabled
    .. method:: put_Enabled
    .. method:: get_Grouping
    .. method:: put_Grouping
    .. method:: get_Profiles
    .. method:: put_Profiles
    .. method:: get_EdgeTraversal
    .. method:: put_EdgeTraversal
    .. method:: get_Action
    .. method:: put_Action


.. class:: INetFwServiceRestriction

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: RestrictService
    .. method:: ServiceRestricted
    .. method:: get_Rules


.. class:: IPersist

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetClassID


.. class:: IPersistFile

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetClassID
    .. method:: IsDirty
    .. method:: Load
    .. method:: Save
    .. method:: SaveCompleted
    .. method:: GetCurFile


.. class:: IShellLinkA

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetPath
    .. method:: GetIDList
    .. method:: SetIDList
    .. method:: GetDescription
    .. method:: SetDescription
    .. method:: GetWorkingDirectory
    .. method:: SetWorkingDirectory
    .. method:: GetArguments
    .. method:: SetArguments
    .. method:: GetHotkey
    .. method:: SetHotkey
    .. method:: GetShowCmd
    .. method:: SetShowCmd
    .. method:: GetIconLocation
    .. method:: SetIconLocation
    .. method:: SetRelativePath
    .. method:: Resolve
    .. method:: SetPath


.. class:: IShellLinkW

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetPath
    .. method:: GetIDList
    .. method:: SetIDList
    .. method:: GetDescription
    .. method:: SetDescription
    .. method:: GetWorkingDirectory
    .. method:: SetWorkingDirectory
    .. method:: GetArguments
    .. method:: SetArguments
    .. method:: GetHotkey
    .. method:: SetHotkey
    .. method:: GetShowCmd
    .. method:: SetShowCmd
    .. method:: GetIconLocation
    .. method:: SetIconLocation
    .. method:: SetRelativePath
    .. method:: Resolve
    .. method:: SetPath


.. class:: ITypeComp

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Bind
    .. method:: BindType


.. class:: ITypeInfo

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeAttr
    .. method:: GetTypeComp
    .. method:: GetFuncDesc
    .. method:: GetVarDesc
    .. method:: GetNames
    .. method:: GetRefTypeOfImplType
    .. method:: GetImplTypeFlags
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: GetDocumentation
    .. method:: GetDllEntry
    .. method:: GetRefTypeInfo
    .. method:: AddressOfMember
    .. method:: CreateInstance
    .. method:: GetMops
    .. method:: GetContainingTypeLib
    .. method:: ReleaseTypeAttr
    .. method:: ReleaseFuncDesc
    .. method:: ReleaseVarDesc


.. class:: ITypeLib

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetTypeInfoType
    .. method:: GetTypeInfoOfGuid
    .. method:: GetLibAttr
    .. method:: GetTypeComp
    .. method:: GetDocumentation
    .. method:: IsName
    .. method:: FindName
    .. method:: ReleaseTLibAttr


.. class:: IUnknown

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release


.. class:: IBackgroundCopyCallback

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: JobTransferred
    .. method:: JobError
    .. method:: JobModification


.. class:: IBackgroundCopyError

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetError
    .. method:: GetFile
    .. method:: GetErrorDescription
    .. method:: GetErrorContextDescription
    .. method:: GetProtocol


.. class:: IBackgroundCopyFile

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetRemoteName
    .. method:: GetLocalName
    .. method:: GetProgress


.. class:: IBackgroundCopyFile2

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetRemoteName
    .. method:: GetLocalName
    .. method:: GetProgress
    .. method:: GetFileRanges
    .. method:: SetRemoteName


.. class:: IBackgroundCopyFile3

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetRemoteName
    .. method:: GetLocalName
    .. method:: GetProgress
    .. method:: GetFileRanges
    .. method:: SetRemoteName
    .. method:: GetTemporaryName
    .. method:: SetValidationState
    .. method:: GetValidationState
    .. method:: IsDownloadedFromPeer


.. class:: IBackgroundCopyJob

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: AddFileSet
    .. method:: AddFile
    .. method:: EnumFiles
    .. method:: Suspend
    .. method:: Resume
    .. method:: Cancel
    .. method:: Complete
    .. method:: GetId
    .. method:: GetType
    .. method:: GetProgress
    .. method:: GetTimes
    .. method:: GetState
    .. method:: GetError
    .. method:: GetOwner
    .. method:: SetDisplayName
    .. method:: GetDisplayName
    .. method:: SetDescription
    .. method:: GetDescription
    .. method:: SetPriority
    .. method:: GetPriority
    .. method:: SetNotifyFlags
    .. method:: GetNotifyFlags
    .. method:: SetNotifyInterface
    .. method:: GetNotifyInterface
    .. method:: SetMinimumRetryDelay
    .. method:: GetMinimumRetryDelay
    .. method:: SetNoProgressTimeout
    .. method:: GetNoProgressTimeout
    .. method:: GetErrorCount
    .. method:: SetProxySettings
    .. method:: GetProxySettings
    .. method:: TakeOwnership


.. class:: IBackgroundCopyJob2

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: AddFileSet
    .. method:: AddFile
    .. method:: EnumFiles
    .. method:: Suspend
    .. method:: Resume
    .. method:: Cancel
    .. method:: Complete
    .. method:: GetId
    .. method:: GetType
    .. method:: GetProgress
    .. method:: GetTimes
    .. method:: GetState
    .. method:: GetError
    .. method:: GetOwner
    .. method:: SetDisplayName
    .. method:: GetDisplayName
    .. method:: SetDescription
    .. method:: GetDescription
    .. method:: SetPriority
    .. method:: GetPriority
    .. method:: SetNotifyFlags
    .. method:: GetNotifyFlags
    .. method:: SetNotifyInterface
    .. method:: GetNotifyInterface
    .. method:: SetMinimumRetryDelay
    .. method:: GetMinimumRetryDelay
    .. method:: SetNoProgressTimeout
    .. method:: GetNoProgressTimeout
    .. method:: GetErrorCount
    .. method:: SetProxySettings
    .. method:: GetProxySettings
    .. method:: TakeOwnership
    .. method:: SetNotifyCmdLine
    .. method:: GetNotifyCmdLine
    .. method:: GetReplyProgress
    .. method:: GetReplyData
    .. method:: SetReplyFileName
    .. method:: GetReplyFileName
    .. method:: SetCredentials
    .. method:: RemoveCredentials


.. class:: IBackgroundCopyManager

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: CreateJob
    .. method:: GetJob
    .. method:: EnumJobs
    .. method:: GetErrorDescription


.. class:: IEnumBackgroundCopyFiles

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Next
    .. method:: Skip
    .. method:: Reset
    .. method:: Clone
    .. method:: GetCount


.. class:: IEnumBackgroundCopyJobs

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Next
    .. method:: Skip
    .. method:: Reset
    .. method:: Clone
    .. method:: GetCount


.. class:: IBindCtx

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: RegisterObjectBound
    .. method:: RevokeObjectBound
    .. method:: ReleaseBoundObjects
    .. method:: SetBindOptions
    .. method:: GetBindOptions
    .. method:: GetRunningObjectTable
    .. method:: RegisterObjectParam
    .. method:: GetObjectParam
    .. method:: EnumObjectParam
    .. method:: RevokeObjectParam


.. class:: IEnumExplorerCommand

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Next
    .. method:: Skip
    .. method:: Reset
    .. method:: Clone


.. class:: IEnumMoniker

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Next
    .. method:: Skip
    .. method:: Reset
    .. method:: Clone


.. class:: IEnumShellItems

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Next
    .. method:: Skip
    .. method:: Reset
    .. method:: Clone


.. class:: IEnumString

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Next
    .. method:: Skip
    .. method:: Reset
    .. method:: Clone


.. class:: IExplorerCommand

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTitle
    .. method:: GetIcon
    .. method:: GetToolTip
    .. method:: GetCanonicalName
    .. method:: GetState
    .. method:: Invoke
    .. method:: GetFlags
    .. method:: EnumSubCommands


.. class:: IMoniker

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetClassID
    .. method:: IsDirty
    .. method:: Load
    .. method:: Save
    .. method:: GetSizeMax
    .. method:: BindToObject
    .. method:: BindToStorage
    .. method:: Reduce
    .. method:: ComposeWith
    .. method:: Enum
    .. method:: IsEqual
    .. method:: Hash
    .. method:: IsRunning
    .. method:: GetTimeOfLastChange
    .. method:: Inverse
    .. method:: CommonPrefixWith
    .. method:: RelativePathTo
    .. method:: GetDisplayName
    .. method:: ParseDisplayName
    .. method:: IsSystemMoniker


.. class:: IRunningObjectTable

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Register
    .. method:: Revoke
    .. method:: IsRunning
    .. method:: GetObject
    .. method:: NoteChangeTime
    .. method:: GetTimeOfLastChange
    .. method:: EnumRunning


.. class:: IShellItem

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: BindToHandler
    .. method:: GetParent
    .. method:: GetDisplayName
    .. method:: GetAttributes
    .. method:: Compare


.. class:: IShellItemArray

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: BindToHandler
    .. method:: GetPropertyStore
    .. method:: GetPropertyDescriptionList
    .. method:: GetAttributes
    .. method:: GetCount
    .. method:: GetItemAt
    .. method:: EnumItems


.. class:: IStream

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Read
    .. method:: Write
    .. method:: Seek
    .. method:: SetSize
    .. method:: CopyTo
    .. method:: Commit
    .. method:: Revert
    .. method:: LockRegion
    .. method:: UnlockRegion
    .. method:: Stat
    .. method:: Clone


.. class:: IApplicationActivationManager

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: ActivateApplication
    .. method:: ActivateForFile
    .. method:: ActivateForProtocol


.. class:: IPackageDebugSettings

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: EnableDebugging
    .. method:: DisableDebugging
    .. method:: Suspend
    .. method:: Resume
    .. method:: TerminateAllProcesses
    .. method:: SetTargetSessionId
    .. method:: EnumerateBackgroundTasks
    .. method:: ActivateBackgroundTask
    .. method:: StartServicing
    .. method:: StopServicing
    .. method:: StartSessionRedirection
    .. method:: StopSessionRedirection
    .. method:: GetPackageExecutionState
    .. method:: RegisterForPackageStateChanges
    .. method:: UnregisterForPackageStateChanges


.. class:: IPackageExecutionStateChangeNotification

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: OnStateChanged


.. class:: IAction

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Id
    .. method:: put_Id
    .. method:: get_Type


.. class:: IActionCollection

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Count
    .. method:: get_Item
    .. method:: get__NewEnum
    .. method:: get_XmlText
    .. method:: put_XmlText
    .. method:: Create
    .. method:: Remove
    .. method:: Clear
    .. method:: get_Context
    .. method:: put_Context


.. class:: IComHandlerAction

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Id
    .. method:: put_Id
    .. method:: get_Type
    .. method:: get_ClassId
    .. method:: put_ClassId
    .. method:: get_Data
    .. method:: put_Data


.. class:: IEmailAction

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Id
    .. method:: put_Id
    .. method:: get_Type
    .. method:: get_Server
    .. method:: put_Server
    .. method:: get_Subject
    .. method:: put_Subject
    .. method:: get_To
    .. method:: put_To
    .. method:: get_Cc
    .. method:: put_Cc
    .. method:: get_Bcc
    .. method:: put_Bcc
    .. method:: get_ReplyTo
    .. method:: put_ReplyTo
    .. method:: get_From
    .. method:: put_From
    .. method:: get_HeaderFields
    .. method:: put_HeaderFields
    .. method:: get_Body
    .. method:: put_Body
    .. method:: get_Attachments
    .. method:: put_Attachments


.. class:: IExecAction

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Id
    .. method:: put_Id
    .. method:: get_Type
    .. method:: get_Path
    .. method:: put_Path
    .. method:: get_Arguments
    .. method:: put_Arguments
    .. method:: get_WorkingDirectory
    .. method:: put_WorkingDirectory


.. class:: IIdleSettings

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_IdleDuration
    .. method:: put_IdleDuration
    .. method:: get_WaitTimeout
    .. method:: put_WaitTimeout
    .. method:: get_StopOnIdleEnd
    .. method:: put_StopOnIdleEnd
    .. method:: get_RestartOnIdle
    .. method:: put_RestartOnIdle


.. class:: INetworkSettings

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Name
    .. method:: put_Name
    .. method:: get_Id
    .. method:: put_Id


.. class:: IPrincipal

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Id
    .. method:: put_Id
    .. method:: get_DisplayName
    .. method:: put_DisplayName
    .. method:: get_UserId
    .. method:: put_UserId
    .. method:: get_LogonType
    .. method:: put_LogonType
    .. method:: get_GroupId
    .. method:: put_GroupId
    .. method:: get_RunLevel
    .. method:: put_RunLevel


.. class:: IRegisteredTask

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Name
    .. method:: get_Path
    .. method:: get_State
    .. method:: get_Enabled
    .. method:: put_Enabled
    .. method:: Run
    .. method:: RunEx
    .. method:: GetInstances
    .. method:: get_LastRunTime
    .. method:: get_LastTaskResult
    .. method:: get_NumberOfMissedRuns
    .. method:: get_NextRunTime
    .. method:: get_Definition
    .. method:: get_Xml
    .. method:: GetSecurityDescriptor
    .. method:: SetSecurityDescriptor
    .. method:: Stop
    .. method:: GetRunTimes


.. class:: IRegisteredTaskCollection

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Count
    .. method:: get_Item
    .. method:: get__NewEnum


.. class:: IRegistrationInfo

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Description
    .. method:: put_Description
    .. method:: get_Author
    .. method:: put_Author
    .. method:: get_Version
    .. method:: put_Version
    .. method:: get_Date
    .. method:: put_Date
    .. method:: get_Documentation
    .. method:: put_Documentation
    .. method:: get_XmlText
    .. method:: put_XmlText
    .. method:: get_URI
    .. method:: put_URI
    .. method:: get_SecurityDescriptor
    .. method:: put_SecurityDescriptor
    .. method:: get_Source
    .. method:: put_Source


.. class:: IRepetitionPattern

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Interval
    .. method:: put_Interval
    .. method:: get_Duration
    .. method:: put_Duration
    .. method:: get_StopAtDurationEnd
    .. method:: put_StopAtDurationEnd


.. class:: IRunningTask

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Name
    .. method:: get_InstanceGuid
    .. method:: get_Path
    .. method:: get_State
    .. method:: get_CurrentAction
    .. method:: Stop
    .. method:: Refresh
    .. method:: get_EnginePID


.. class:: IRunningTaskCollection

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Count
    .. method:: get_Item
    .. method:: get__NewEnum


.. class:: IShowMessageAction

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Id
    .. method:: put_Id
    .. method:: get_Type
    .. method:: get_Title
    .. method:: put_Title
    .. method:: get_MessageBody
    .. method:: put_MessageBody


.. class:: ITaskDefinition

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_RegistrationInfo
    .. method:: put_RegistrationInfo
    .. method:: get_Triggers
    .. method:: put_Triggers
    .. method:: get_Settings
    .. method:: put_Settings
    .. method:: get_Data
    .. method:: put_Data
    .. method:: get_Principal
    .. method:: put_Principal
    .. method:: get_Actions
    .. method:: put_Actions
    .. method:: get_XmlText
    .. method:: put_XmlText


.. class:: ITaskFolder

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Name
    .. method:: get_Path
    .. method:: GetFolder
    .. method:: GetFolders
    .. method:: CreateFolder
    .. method:: DeleteFolder
    .. method:: GetTask
    .. method:: GetTasks
    .. method:: DeleteTask
    .. method:: RegisterTask
    .. method:: RegisterTaskDefinition
    .. method:: GetSecurityDescriptor
    .. method:: SetSecurityDescriptor


.. class:: ITaskFolderCollection

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Count
    .. method:: get_Item
    .. method:: get__NewEnum


.. class:: ITaskNamedValueCollection

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Count
    .. method:: get_Item
    .. method:: get__NewEnum
    .. method:: Create
    .. method:: Remove
    .. method:: Clear


.. class:: ITaskNamedValuePair

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Name
    .. method:: put_Name
    .. method:: get_Value
    .. method:: put_Value


.. class:: ITaskService

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: GetFolder
    .. method:: GetRunningTasks
    .. method:: NewTask
    .. method:: Connect
    .. method:: get_Connected
    .. method:: get_TargetServer
    .. method:: get_ConnectedUser
    .. method:: get_ConnectedDomain
    .. method:: get_HighestVersion


.. class:: ITaskSettings

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_AllowDemandStart
    .. method:: put_AllowDemandStart
    .. method:: get_RestartInterval
    .. method:: put_RestartInterval
    .. method:: get_RestartCount
    .. method:: put_RestartCount
    .. method:: get_MultipleInstances
    .. method:: put_MultipleInstances
    .. method:: get_StopIfGoingOnBatteries
    .. method:: put_StopIfGoingOnBatteries
    .. method:: get_DisallowStartIfOnBatteries
    .. method:: put_DisallowStartIfOnBatteries
    .. method:: get_AllowHardTerminate
    .. method:: put_AllowHardTerminate
    .. method:: get_StartWhenAvailable
    .. method:: put_StartWhenAvailable
    .. method:: get_XmlText
    .. method:: put_XmlText
    .. method:: get_RunOnlyIfNetworkAvailable
    .. method:: put_RunOnlyIfNetworkAvailable
    .. method:: get_ExecutionTimeLimit
    .. method:: put_ExecutionTimeLimit
    .. method:: get_Enabled
    .. method:: put_Enabled
    .. method:: get_DeleteExpiredTaskAfter
    .. method:: put_DeleteExpiredTaskAfter
    .. method:: get_Priority
    .. method:: put_Priority
    .. method:: get_Compatibility
    .. method:: put_Compatibility
    .. method:: get_Hidden
    .. method:: put_Hidden
    .. method:: get_IdleSettings
    .. method:: put_IdleSettings
    .. method:: get_RunOnlyIfIdle
    .. method:: put_RunOnlyIfIdle
    .. method:: get_WakeToRun
    .. method:: put_WakeToRun
    .. method:: get_NetworkSettings
    .. method:: put_NetworkSettings


.. class:: ITrigger

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Type
    .. method:: get_Id
    .. method:: put_Id
    .. method:: get_Repetition
    .. method:: put_Repetition
    .. method:: get_ExecutionTimeLimit
    .. method:: put_ExecutionTimeLimit
    .. method:: get_StartBoundary
    .. method:: put_StartBoundary
    .. method:: get_EndBoundary
    .. method:: put_EndBoundary
    .. method:: get_Enabled
    .. method:: put_Enabled


.. class:: ITriggerCollection

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: get_Count
    .. method:: get_Item
    .. method:: get__NewEnum
    .. method:: Create
    .. method:: Remove
    .. method:: Clear


.. class:: IWebBrowser2

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetTypeInfoCount
    .. method:: GetTypeInfo
    .. method:: GetIDsOfNames
    .. method:: Invoke
    .. method:: GoBack
    .. method:: GoForward
    .. method:: GoHome
    .. method:: GoSearch
    .. method:: Navigate
    .. method:: Refresh
    .. method:: Refresh2
    .. method:: Stop
    .. method:: get_Application
    .. method:: get_Parent
    .. method:: get_Container
    .. method:: get_Document
    .. method:: get_TopLevelContainer
    .. method:: get_Type
    .. method:: get_Left
    .. method:: put_Left
    .. method:: get_Top
    .. method:: put_Top
    .. method:: get_Width
    .. method:: put_Width
    .. method:: get_Height
    .. method:: put_Height
    .. method:: get_LocationName
    .. method:: get_LocationURL
    .. method:: get_Busy
    .. method:: Quit
    .. method:: ClientToWindow
    .. method:: PutProperty
    .. method:: GetProperty
    .. method:: get_Name
    .. method:: get_HWND
    .. method:: get_FullName
    .. method:: get_Path
    .. method:: get_Visible
    .. method:: put_Visible
    .. method:: get_StatusBar
    .. method:: put_StatusBar
    .. method:: get_StatusText
    .. method:: put_StatusText
    .. method:: get_ToolBar
    .. method:: put_ToolBar
    .. method:: get_MenuBar
    .. method:: put_MenuBar
    .. method:: get_FullScreen
    .. method:: put_FullScreen
    .. method:: Navigate2
    .. method:: QueryStatusWB
    .. method:: ExecWB
    .. method:: ShowBrowserBar
    .. method:: get_ReadyState
    .. method:: get_Offline
    .. method:: put_Offline
    .. method:: get_Silent
    .. method:: put_Silent
    .. method:: get_RegisterAsBrowser
    .. method:: put_RegisterAsBrowser
    .. method:: get_RegisterAsDropTarget
    .. method:: put_RegisterAsDropTarget
    .. method:: get_TheaterMode
    .. method:: put_TheaterMode
    .. method:: get_AddressBar
    .. method:: put_AddressBar
    .. method:: get_Resizable
    .. method:: put_Resizable


.. class:: IEnumWbemClassObject

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Reset
    .. method:: Next
    .. method:: NextAsync
    .. method:: Clone
    .. method:: Skip


.. class:: IWbemCallResult

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetResultObject
    .. method:: GetResultString
    .. method:: GetResultServices
    .. method:: GetCallStatus


.. class:: IWbemClassObject

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetQualifierSet
    .. method:: Get
    .. method:: Put
    .. method:: Delete
    .. method:: GetNames
    .. method:: BeginEnumeration
    .. method:: Next
    .. method:: EndEnumeration
    .. method:: GetPropertyQualifierSet
    .. method:: Clone
    .. method:: GetObjectText
    .. method:: SpawnDerivedClass
    .. method:: SpawnInstance
    .. method:: CompareTo
    .. method:: GetPropertyOrigin
    .. method:: InheritsFrom
    .. method:: GetMethod
    .. method:: PutMethod
    .. method:: DeleteMethod
    .. method:: BeginMethodEnumeration
    .. method:: NextMethod
    .. method:: EndMethodEnumeration
    .. method:: GetMethodQualifierSet
    .. method:: GetMethodOrigin


.. class:: IWbemContext

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Clone
    .. method:: GetNames
    .. method:: BeginEnumeration
    .. method:: Next
    .. method:: EndEnumeration
    .. method:: SetValue
    .. method:: GetValue
    .. method:: DeleteValue
    .. method:: DeleteAll


.. class:: IWbemLocator

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: ConnectServer


.. class:: IWbemObjectSink

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Indicate
    .. method:: SetStatus


.. class:: IWbemObjectTextSrc

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: GetText
    .. method:: CreateFromText


.. class:: IWbemQualifierSet

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: Get
    .. method:: Put
    .. method:: Delete
    .. method:: GetNames
    .. method:: BeginEnumeration
    .. method:: Next
    .. method:: EndEnumeration


.. class:: IWbemServices

    .. method:: QueryInterface
    .. method:: AddRef
    .. method:: Release
    .. method:: OpenNamespace
    .. method:: CancelAsyncCall
    .. method:: QueryObjectSink
    .. method:: GetObject
    .. method:: GetObjectAsync
    .. method:: PutClass
    .. method:: PutClassAsync
    .. method:: DeleteClass
    .. method:: DeleteClassAsync
    .. method:: CreateClassEnum
    .. method:: CreateClassEnumAsync
    .. method:: PutInstance
    .. method:: PutInstanceAsync
    .. method:: DeleteInstance
    .. method:: DeleteInstanceAsync
    .. method:: CreateInstanceEnum
    .. method:: CreateInstanceEnumAsync
    .. method:: ExecQuery
    .. method:: ExecQueryAsync
    .. method:: ExecNotificationQuery
    .. method:: ExecNotificationQueryAsync
    .. method:: ExecMethod
    .. method:: ExecMethodAsync


