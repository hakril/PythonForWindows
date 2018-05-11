import windows.com
import windows.generated_def as gdef


def generate_simple_getter(function, restype, extract_value=True):
    @property
    def value_getter(self):
        res = restype()
        getattr(self, function)(res)
        if extract_value:
            return res.value
        return res
    return value_getter


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
        # TODO: ImprovedVariant.from_int()
        # vindex = windows.com.ImprovedVariant()
        # vindex.vt = gdef.VT_I4
        # vindex._VARIANT_NAME_3.lVal = index
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
        return list(self.items_generator())

    def __iter__(self):
        return self.items_generator()

    def __getitem__(self, index): # Allow subclasses to only overwrite 'get_item' to rewrite both behavior
        return self.get_item(index)






class AbstractAction(object):
    type = generate_simple_getter("get_Type", gdef.TASK_ACTION_TYPE)
    id = generate_simple_getter("get_Id", gdef.BSTR)

class Action(gdef.IAction, AbstractAction):
    ACTION_SUBTYPE = {
        gdef.TASK_ACTION_SEND_EMAIL: gdef.IEmailAction,
        gdef.TASK_ACTION_SHOW_MESSAGE: gdef.IShowMessageAction
    }



    @property
    def subtype(self):
        subinterface = self.ACTION_SUBTYPE[self.type] # KeyError ?
        return self.query(subinterface)


class ExecAction(gdef.IExecAction, AbstractAction):
    path = generate_simple_getter("get_Path", gdef.BSTR)
    path = add_simple_setter(path, "put_Path", gdef.BSTR)

    arguments = generate_simple_getter("get_Arguments", gdef.BSTR)
    arguments = add_simple_setter(arguments, "put_Arguments", gdef.BSTR)

    working_directory = generate_simple_getter("get_WorkingDirectory", gdef.BSTR)

# Register action subtype
Action.ACTION_SUBTYPE[gdef.TASK_ACTION_EXEC] = ExecAction

class ComHandlerAction(gdef.IComHandlerAction, AbstractAction):
    classid = generate_simple_getter("get_ClassId", gdef.BSTR)
    classid = add_simple_setter(classid, "put_ClassId", gdef.BSTR)
    data = generate_simple_getter("get_Data", gdef.BSTR)
    data = add_simple_setter(data, "put_Data", gdef.BSTR)

# Register action subtype
Action.ACTION_SUBTYPE[gdef.TASK_ACTION_COM_HANDLER] = ComHandlerAction


class Trigger(gdef.ITrigger):
    type = generate_simple_getter("get_Type", gdef.TASK_TRIGGER_TYPE2)


class ActionCollection(gdef.IActionCollection,  TaskCollectionType):
    ITEM_TYPE = Action

    def create(self, action_type):
        res = self.ITEM_TYPE()
        self.Create(action_type, res)
        return res.subtype

    def get_item(self, index):
        item = super(ActionCollection, self).get_item(index)
        # Need to Release() item ?
        return item.subtype

class TriggerCollection(gdef.ITriggerCollection,  TaskCollectionType):
    ITEM_TYPE = Trigger


class TaskDefinition(gdef.ITaskDefinition):
    actions = generate_simple_getter("get_Actions", ActionCollection, extract_value=False)
    triggers = generate_simple_getter("get_Triggers", TriggerCollection, extract_value=False)


class Task(gdef.IRegisteredTask):
    name = generate_simple_getter("get_Name", gdef.BSTR)
    path = generate_simple_getter("get_Path", gdef.BSTR)
    state = generate_simple_getter("get_State", gdef.TASK_STATE)
    definition = generate_simple_getter("get_Definition", TaskDefinition, extract_value=False)

    def run(self, params=None, flags=gdef.TASK_RUN_NO_FLAGS, sessionid=0, user=None):
        if params is None: params = gdef.VARIANT() # Empty variant
        result = gdef.IRunningTask()
        self.RunEx(params, flags, sessionid, user, result)
        return result

    def __repr__(self):
        return """<{0} "{1}" at {2:#x}>""".format(type(self).__name__, self.name, id(self))


class TaskCollection(gdef.IRegisteredTaskCollection, TaskCollectionType):
    ITEM_TYPE = Task
    def get_index(self, index):
        vindex = windows.com.ImprovedVariant()
        vindex.vt = gdef.VT_I4
        vindex._VARIANT_NAME_3.lVal = index
        return vindex


class TaskService(gdef.ITaskService):
    def create(self, flags=0):
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
        folder = TaskFolder()
        self.GetFolder(name, folder)
        return folder

    __call__ = folder # use the same 'API' than the registry


    @property
    def root(self):
        return self.folder("\\")



class TaskFolder(gdef.ITaskFolder):
    path = generate_simple_getter("get_Path", gdef.BSTR)
    name = generate_simple_getter("get_Name", gdef.BSTR)

    @property
    def folders(self):
        res = TaskFolderCollection()
        self.GetFolders(0, res)
        return res

    def register(self, path, taskdef, flags=gdef.TASK_CREATE, userid=None, password=None, logonType=gdef.TASK_LOGON_NONE, ssid=None):
        new_task =  Task()

        if userid is None: userid = gdef.VARIANT() # Empty variant
        if password is None: password = gdef.VARIANT() # Empty variant
        if ssid is None: ssid = gdef.VARIANT() # Empty variant

        self.RegisterTaskDefinition(path, taskdef, flags, userid, password, logonType, ssid, new_task)
        return new_task

    @property
    def tasks(self, flags=gdef.TASK_ENUM_HIDDEN):
        tasks = TaskCollection()
        self.GetTasks(flags, tasks)
        return tasks

    def get_task(self, name):
        res = Task()
        self.GetTask(name, res)
        return res

    def delete_task(self, name):
        return self.DeleteTask(name, 0)

    def folder(self, name):
        folder = TaskFolder()
        self.GetFolder(name, folder)
        return folder

    def create_folder(self, name):
        folder = TaskFolder()
        self.CreateFolder(name, gdef.VARIANT(), folder)
        return folder

    def delete_folder(self, name):
        return self.DeleteFolder(name, 0)

    __getitem__ = get_task
    __delitem__ = delete_task
    __call__ = folder # use the same 'API' than the registry



    def __repr__(self):
        return """<{0} "{1}" at {2:#x}>""".format(type(self).__name__, self.path, id(self))


class TaskFolderCollection(gdef.ITaskFolderCollection, TaskCollectionType):
    ITEM_TYPE = TaskFolder

    def get_index(self, index):
        vindex = windows.com.ImprovedVariant()
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