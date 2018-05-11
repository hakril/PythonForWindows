import sys
import os.path
import pprint
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.generated_def as gdef

tscheduler = windows.system.task_scheduler
print("Task scheduler is {0}".format(tscheduler))
root = tscheduler.root
print("Root folder is {0}".format(root))
print ("Listing sub folders")
for subfolder in root.folders:
    print("   * {0}".format(subfolder))
    last_name = subfolder.name

demo_folder = "\Microsoft\Windows\AppID"
print("Manually opening subfolder <{0}>".format(demo_folder))
subfolder = root(demo_folder)
print("Working into {0}".format(subfolder))
for task in subfolder.tasks:
    print("   * {task.name}".format(task=task))

print("")
print("Analysing task {task}".format(task=task))
print("   * Name: <{task.name}>".format(task=task))
print("   * Path: <{task.path}>".format(task=task))
print("   * Definition: <{task.definition}>".format(task=task))
print("Listing actions:")
for action in task.definition.actions:
    print("   * Action: <{action}>".format(action=action))
    print("     * Type: <{action.type}>".format(action=action))
    if getattr(action, "path", None):
        print("     * path: <{action.path}>".format(action=action))
        print("     * arguments: <{action.arguments}>".format(action=action))

    # import pdb;pdb.set_trace()
print("Listing triggers:")
for trigger in task.definition.triggers:
    print("   * Trigger type: <{trigger.type}>".format(trigger=trigger))

print("")
DEMO_FOLDER_NAME = "PFW_DEMO_FOLDER"
DEMO_TASK_NAME = "PFW_DEMO_TASK"
print("Creating folder <{0}>".format(DEMO_FOLDER_NAME))
demo_folder = root.create_folder(DEMO_FOLDER_NAME)
print("Demo folder is {0}".format(demo_folder))

print("Creating Task definition")
# Create a Task definition
new_task_definition = tscheduler.create()
actions = new_task_definition.actions
# Add an TASK_ACTION_EXEC action to the task def
new_action = actions.create(gdef.TASK_ACTION_EXEC)
new_action.path = sys.executable
new_action.arguments = "-c 'Hello !'"
# Register the new task under 'DEMO_TASK_NAME'
print("Registering task definition as <{0}> in <{1}>".format(DEMO_TASK_NAME, demo_folder))
new_task = demo_folder.register(DEMO_TASK_NAME, new_task_definition)
print("Created task is {0}".format(new_task))

print("Deleting the demo task")
del demo_folder[DEMO_TASK_NAME]
print("Deleting the demo folder")
root.delete_folder(DEMO_FOLDER_NAME)

