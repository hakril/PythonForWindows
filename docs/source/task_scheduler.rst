Task scheduler
==============

.. module:: windows.winobject.task_scheduler

.. note::

    See sample :ref:`sample_scheduled_task`


TaskService
"""""""""""

.. autoclass:: TaskService
    :show-inheritance:
    :special-members: __call__

TaskFolder
"""""""""""

.. autoclass:: TaskFolder
    :show-inheritance:
    :special-members: __getitem__, __delitem__, __call__


Task
""""

.. autoclass:: Task
    :show-inheritance:
    :special-members: __getitem__, __delitem__, __call__

TaskDefinition
""""""""""""""

.. autoclass:: TaskDefinition
    :show-inheritance:
    :special-members: __getitem__, __delitem__, __call__

Action
""""""

Action
''''''

.. autoclass:: Action
    :show-inheritance:
    :inherited-members:
    :special-members: __getitem__, __delitem__, __call__


ExecAction
''''''''''

.. autoclass:: ExecAction
    :show-inheritance:
    :inherited-members:
    :special-members: __getitem__, __delitem__, __call__


ComHandlerAction
''''''''''''''''

.. autoclass:: ComHandlerAction
    :show-inheritance:
    :inherited-members:
    :special-members: __getitem__, __delitem__, __call__


Trigger
"""""""

.. autoclass:: Trigger
    :show-inheritance:
    :special-members: __getitem__, __delitem__, __call__


Collections
"""""""""""

TaskFolderCollection
''''''''''''''''''''

.. autoclass:: TaskFolderCollection
    :show-inheritance:
    :special-members: __getitem__, __delitem__, __call__

TaskCollection
''''''''''''''

.. autoclass:: TaskCollection
    :show-inheritance:
    :special-members: __getitem__, __delitem__, __call__

ActionCollection
''''''''''''''''

.. autoclass:: ActionCollection
    :show-inheritance:
    :special-members: __getitem__, __delitem__, __call__

TriggerCollection
'''''''''''''''''

.. autoclass:: TriggerCollection
    :show-inheritance:
    :special-members: __getitem__, __delitem__, __call__

