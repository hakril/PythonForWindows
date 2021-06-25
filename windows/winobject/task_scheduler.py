import windows.com
import windows.generated_def as gdef


def generate_simple_getter(function, restype, extract_value=True, doc=None):
    def value_getter(self):
        res = restype()
        getattr(self, function)(res)
        if extract_value:
            return res.value
        return res
    return property(value_getter, doc=doc)


def add_simple_setter(getter, function, restype):
    @getter.setter
    def value_setter(self, value):
        resvalue = restype(value)
        return getattr(self, function)(resvalue)
    return value_setter


class TaskCollectionType(object):
    ITEM_TYPE = None

    count = generate_simple_getter("get_Count", gdef.LONG)

    def get_item_type(self):
        return self.ITEM_TYPE

    def get_item(self, index):
        """Return elements nb ``index``. Collection index starts at 1"""
        if index == 0:
            raise IndexError("<{0}> Index start as 1".format(type(self).__name__))
        index = self.get_index(index)
        res = self.get_item_type()()
        self.get_Item(index, res)
        return res

    def get_index(self, index):
        return index

    def items_generator(self):
        for i in range(self.count):
            # Start index is 1
            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa446901(v=vs.85).aspx
            yield self.get_item(1 + i)

    @property
    def items(self):
        """Return the list of item in the collection

        :type: :class:`list`
        """
        return list(self.items_generator())

    def __iter__(self):
        return self.items_generator()

    def __getitem__(self, index): # Allow subclasses to only overwrite 'get_item' to rewrite both behavior
        return self.get_item(index)

# Need to-do the doc=xx tricks to have the documentation in the 'AbstractAction' subclasses

class AbstractAction(object):
    type_doc = """The type of action

    :type: :class:`~windows.generated_def.winstructs.TASK_ACTION_TYPE`
    """
    type = generate_simple_getter("get_Type", gdef.TASK_ACTION_TYPE, doc=type_doc)

    id_doc = """The action id

    :type: :class:`~windows.generated_def.winstructs.BSTR`
    """
    id = generate_simple_getter("get_Id", gdef.BSTR, doc=id_doc)


class Action(gdef.IAction, AbstractAction):
    """Describe an action performed by a task"""
    ACTION_SUBTYPE = {}


    @property
    def subtype(self):
        """Return the :class:`Action`-subtype according to :data:`AbstractAction.type`"""
        subinterface = self.ACTION_SUBTYPE[self.type] # KeyError ?
        return self.query(subinterface)


class ExecAction(gdef.IExecAction, AbstractAction):
    """Represent an action of type
        :data:`~windows.generated_def.winstructs._TASK_ACTION_TYPE.TASK_ACTION_EXEC`"""
    path = generate_simple_getter("get_Path", gdef.BSTR)
    path = add_simple_setter(path, "put_Path", gdef.BSTR)
    """[R-W] The path of the programm to execute"""

    arguments = generate_simple_getter("get_Arguments", gdef.BSTR)
    arguments = add_simple_setter(arguments, "put_Arguments", gdef.BSTR)
    """[R-W] The arguments for the command to execute"""

    working_directory = generate_simple_getter("get_WorkingDirectory", gdef.BSTR)
    """The working directory for the command to execute"""

# Register action subtype
Action.ACTION_SUBTYPE[gdef.TASK_ACTION_EXEC] = ExecAction

class ComHandlerAction(gdef.IComHandlerAction, AbstractAction):
    """Represent an action of type
        :data:`~windows.generated_def.winstructs._TASK_ACTION_TYPE.TASK_ACTION_COM_HANDLER`"""

    classid = generate_simple_getter("get_ClassId", gdef.BSTR)
    classid = add_simple_setter(classid, "put_ClassId", gdef.BSTR)
    """The CLSID of the COM server executed

    :type: :class:`~windows.generated_def.winstructs.BSTR`
    """
    data = generate_simple_getter("get_Data", gdef.BSTR)
    data = add_simple_setter(data, "put_Data", gdef.BSTR)
    """The DATA for the COM class

    :type: :class:`~windows.generated_def.winstructs.BSTR`
    """

# Register action subtype
Action.ACTION_SUBTYPE[gdef.TASK_ACTION_COM_HANDLER] = ComHandlerAction


class EmailAction(gdef.IEmailAction, AbstractAction):
    pass


Action.ACTION_SUBTYPE[gdef.TASK_ACTION_SEND_EMAIL] = EmailAction

class ShowMessageAction(gdef.IShowMessageAction, AbstractAction):
    pass

Action.ACTION_SUBTYPE[gdef.TASK_ACTION_SHOW_MESSAGE] = ShowMessageAction

class Trigger(gdef.ITrigger):
    """A task trigger"""
    type = generate_simple_getter("get_Type", gdef.TASK_TRIGGER_TYPE2)
    """The type of trigger

    :type: :class:`~windows.generated_def.winstructs.TASK_TRIGGER_TYPE2`
    """


class ActionCollection(gdef.IActionCollection,  TaskCollectionType):
    ITEM_TYPE = Action

    def create(self, action_type):
        """Create a new action of type ``action_type``

        :rtype: A subclass of :class:`Action`
        """
        res = self.ITEM_TYPE()
        self.Create(action_type, res)
        return res.subtype

    def get_item(self, index):
        item = super(ActionCollection, self).get_item(index)
        # Need to Release() item ?
        return item.subtype

class TriggerCollection(gdef.ITriggerCollection,  TaskCollectionType):
    ITEM_TYPE = Trigger


class TaskRegistrationInfo(gdef.IRegistrationInfo):
    """Provides the administrative information that can be used to describe the task.

    This information includes details such as a description of the task,
    the author of the task, the date the task is registered,
    and the security descriptor of the task.
    """
    author = generate_simple_getter("get_Author", gdef.BSTR)
    """The author of the task"""
    description = generate_simple_getter("get_Description", gdef.BSTR)
    """The description of the task"""
    date = generate_simple_getter("get_Date", gdef.BSTR)
    """The registration date of the task"""
    source = generate_simple_getter("get_Source", gdef.BSTR)
    """Where the task originated from.

    For example, a task may originate from a component, service, application, or user.
    """
    documentation = generate_simple_getter("get_Documentation", gdef.BSTR)
    """Any additional documentation for the task"""
    uri = generate_simple_getter("get_URI", gdef.BSTR)
    """the URI of the task."""
    version = generate_simple_getter("get_Version", gdef.BSTR)
    """The version number of the task."""

    # Return WindowsError: [Error -2147467263] Not implemented
    # xml = generate_simple_getter("get_XmlText", gdef.BSTR)

    sddl = generate_simple_getter("get_SecurityDescriptor", windows.com.Variant)

    @property
    def security_descriptor(self):
        sddl = self.sddl
        if not sddl:
            return None
        return windows.security.SecurityDescriptor.from_string(sddl)



class TaskPrincipal(gdef.IPrincipal):
    """Provides the security credentials for a principal.
    These security credentials define the security context for the tasks that are associated with the principal.
    """

    name = generate_simple_getter("get_DisplayName", gdef.BSTR)
    name = add_simple_setter(name, "put_DisplayName", gdef.BSTR)
    """The name of the principal"""
    id = generate_simple_getter("get_Id", gdef.BSTR)
    id = add_simple_setter(id, "put_Id", gdef.BSTR)
    """the identifier of the principal."""
    user_id = generate_simple_getter("get_UserId", gdef.BSTR)
    user_id = add_simple_setter(user_id, "put_UserId", gdef.BSTR)
    """the user identifier that is required to run the task"""
    group_id = generate_simple_getter("get_GroupId", gdef.BSTR)
    group_id = add_simple_setter(group_id, "put_GroupId", gdef.BSTR)
    """the user group that is required to run the task"""
    run_level = generate_simple_getter("get_RunLevel", gdef.TASK_RUNLEVEL_TYPE)
    """the privilege level that is required to run the tasks

    :type: :class:`~windows.generated_def.winstructs.TASK_RUNLEVEL_TYPE`
    """
    logon_type = generate_simple_getter("get_LogonType", gdef.TASK_LOGON_TYPE)
    """ logon method that is required to run the task

    :type: :class:`~windows.generated_def.winstructs.TASK_LOGON_TYPE`
    """

class TaskDefinition(gdef.ITaskDefinition):
    """The definition of a task"""
    actions = generate_simple_getter("get_Actions", ActionCollection, extract_value=False)
    """The list of actions of the task

    :type: :class:`ActionCollection`
    """
    triggers = generate_simple_getter("get_Triggers", TriggerCollection, extract_value=False)
    """The list of triggers of the task

    :type: :class:`TriggerCollection`
    """

    registration_info = generate_simple_getter("get_RegistrationInfo", TaskRegistrationInfo, extract_value=False)
    """The registration information of the task

    :type: :class:`TaskRegistrationInfo`
    """

    principal = generate_simple_getter("get_Principal", TaskPrincipal, extract_value=False)
    """The principal that provides the security credentials for the task.
    These security credentials define the security context for the tasks that are associated with the principal.

    :type: :class:`TaskPrincipal`
    """

    xml = generate_simple_getter("get_XmlText", gdef.BSTR)
    """The XML representig the task definition

        :type: :class:`str`
    """



class Task(gdef.IRegisteredTask):
    """A scheduled task"""
    name = generate_simple_getter("get_Name", gdef.BSTR)
    """The name of the task"""
    path = generate_simple_getter("get_Path", gdef.BSTR)
    """The path of the task"""
    state = generate_simple_getter("get_State", gdef.TASK_STATE)
    """The state of the task


        :type: :class:`~windows.generated_def.winstructs.TASK_STATE`
    """
    enabled = generate_simple_getter("get_Enabled", gdef.VARIANT_BOOL)
    """``True`` is the task is enabled"""
    last_runtime = generate_simple_getter("get_LastRunTime", gdef.DATE)
    """Gets the last time the registered task was last run."""
    next_runtime = generate_simple_getter("get_NextRunTime", gdef.DATE)
    """Gets the next time the registered task will be run."""

    definition = generate_simple_getter("get_Definition", TaskDefinition, extract_value=False)
    """The definition of the task

        :type: :class:`TaskDefinition`
    """

    xml = generate_simple_getter("get_Xml", gdef.BSTR)
    """The XML representig the task

        :type: :class:`str`
    """

    def run(self, params=None, flags=gdef.TASK_RUN_NO_FLAGS, sessionid=0, user=None):
        if params is None: params = gdef.VARIANT() # Empty variant
        result = gdef.IRunningTask()
        self.RunEx(params, flags, sessionid, user, result)
        return result

    def get_security_descriptor(self, secinfo):
        res = gdef.BSTR()
        self.GetSecurityDescriptor(secinfo, res)
        return res.value

    def __repr__(self):
        return """<{0} "{1}" at {2:#x}>""".format(type(self).__name__, self.name, id(self))


class TaskCollection(gdef.IRegisteredTaskCollection, TaskCollectionType):
    ITEM_TYPE = Task
    def get_index(self, index):
        vindex = windows.com.Variant()
        vindex.vt = gdef.VT_I4
        vindex._VARIANT_NAME_3.lVal = index
        return vindex


class TaskService(gdef.ITaskService):
    """The task scheduler"""
    def create(self, flags=0):
        """Create a new :class:`TaskDefinition` that can be used to create/register a new scheduled task

        :rtype: :class:`TaskDefinition`
        """
        res = TaskDefinition()
        self.NewTask(flags, res)
        return res

    def connect(self, server=None, user=None, domain=None, password=None):
        if server is None: server = gdef.VARIANT() # Empty variant
        if user is None: user = gdef.VARIANT() # Empty variant
        if domain is None: domain = gdef.VARIANT() # Empty variant
        if password is None: password = gdef.VARIANT() # Empty variant
        self.Connect(server, user, domain, password)

    def folder(self, name):
        """Return the :class:`TaskFolder` with ``name``

        :rtype: :class:`TaskFolder`
        """
        folder = TaskFolder()
        self.GetFolder(name, folder)
        return folder

    __call__ = folder # use the same 'API' than the registry
    """Alias for :func:`folder`"""


    @property
    def root(self):
        r"""The root ``\`` :class:`TaskFolder`"""
        return self.folder("\\")



class TaskFolder(gdef.ITaskFolder):
    """A folder of tasks"""
    path = generate_simple_getter("get_Path", gdef.BSTR)
    name = generate_simple_getter("get_Name", gdef.BSTR)

    @property
    def folders(self):
        """The list of sub-folders

        :type: :class:`TaskFolderCollection`
        """
        res = TaskFolderCollection()
        self.GetFolders(0, res)
        return res

    def register(self, name, taskdef, flags=gdef.TASK_CREATE, userid=None, password=None, logonType=gdef.TASK_LOGON_NONE, ssid=None):
        """Register the task definition ``taskdef`` as a new task with ``name``

        :rtype: :class:`Task`
        """
        new_task =  Task()

        if userid is None: userid = gdef.VARIANT() # Empty variant
        if password is None: password = gdef.VARIANT() # Empty variant
        if ssid is None: ssid = gdef.VARIANT() # Empty variant

        self.RegisterTaskDefinition(name, taskdef, flags, userid, password, logonType, ssid, new_task)
        return new_task

    @property
    def tasks(self, flags=gdef.TASK_ENUM_HIDDEN):
        """The list of tasks in the folder

        :type: :class:`TaskCollection`
        """
        tasks = TaskCollection()
        self.GetTasks(flags, tasks)
        return tasks

    def get_task(self, name):
        """Retrieve the task with ``name`` in the current folder

        :rtype: :class:`Task`
        """
        res = Task()
        self.GetTask(name, res)
        return res

    def delete_task(self, name):
        """Delete the task with ``name`` in the current folder"""
        return self.DeleteTask(name, 0)

    def folder(self, name):
        """Return the :class:`TaskFolder` with ``name``"""
        folder = TaskFolder()
        self.GetFolder(name, folder)
        return folder

    def create_folder(self, name):
        """Create a new sub-:class:`TaskFolder` with ``name``"""
        folder = TaskFolder()
        self.CreateFolder(name, gdef.VARIANT(), folder)
        return folder

    def delete_folder(self, name):
        """Delete the sub-folder with ``name`` in the current folder"""
        return self.DeleteFolder(name, 0)

    __getitem__ = get_task
    """ Alias for :func:`get_task`"""
    __delitem__ = delete_task
    """ Alias for :func:`delete_task`"""
    __call__ = folder # use the same 'API' than the registry
    """ Alias for :func:`folder`"""



    def __repr__(self):
        return """<{0} "{1}" at {2:#x}>""".format(type(self).__name__, self.path, id(self))


class TaskFolderCollection(gdef.ITaskFolderCollection, TaskCollectionType):
    ITEM_TYPE = TaskFolder

    def get_index(self, index):
        vindex = windows.com.Variant()
        vindex.vt = gdef.VT_I4
        vindex._VARIANT_NAME_3.lVal = index
        return vindex

# windows.com.init()
# clsid_task_scheduler = gdef.IID.from_string("0f87369f-a4e5-4cfc-bd3e-73e6154572dd")
# x = TaskService()
# emptvar = gdef.VARIANT()
# windows.com.create_instance(clsid_task_scheduler, x)
# x.connect()
# folder = x.folder("\\")
# assert folder.value
# tasks = folder.tasks

# for task in tasks.items:
    # print(task.name)
    # for action in task.definition.actions.items:
        # print("   * {0}".format(action.type))
        # subtype = action.subtype
        # print("   * Path: {0}".format(subtype.path))
        # print("   * Args: {0}".format(subtype.arguments))
        # print("   * WDir: {0}".format(subtype.working_directory))

# Test creation

# ntd = x.create()
# actions = ntd.actions
# nea = actions.create(gdef.TASK_ACTION_EXEC).subtype
# nea.path = "MY_BINARY"
# nea.arguments = "MY_ARGUMENTS"

# folder.register("PROUT", ntd)

# path = gdef.BSTR()
# e.get_Path(path)
# print(path)