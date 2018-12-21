``windows.security`` -- Security Descriptor & related
*****************************************************

.. warning:

    Foutre les token ici ?
    Ca a du sens https://docs.microsoft.com/en-us/windows/desktop/secauthz/access-control-components

    ACCESS CONTROL TOUT CA..
    Les deux  vont bien ensemble..


.. module:: windows.security

This module give access to :class:`SecurityDescriptor` and related structures (``Acl`` & ``Ace``).

.. note::

    See sample :ref:`sample_security`

Token
"""""

The :mod:`windows.security` module is the official module where to retrieve the :class:`~windows.winobject.token.Token` class if ever needed.

Indeed ``SecurityDescriptor`` & ``Token`` are deeply related and I may move ``token.py`` to a ``security/`` directory in the futur.


    >>> windows.security.Token
    <class 'windows.winobject.token.Token'>


SecurityDescriptor
""""""""""""""""""

.. autoclass:: SecurityDescriptor


Acl
"""

.. autoclass:: Acl
    :special-members: __len__, __iter__


.. _security_ace:

Ace
"""

The ACE are regrouped in two categories.

The DACL related ACEs:

    - :class:`AccessAllowedACE`
    - :class:`AccessDeniedACE`
    - :class:`AccessAllowedCallbackACE`
    - :class:`AccessDeniedCallbackACE`
    - :class:`AccessAllowedObjectACE`
    - :class:`AccessDeniedObjectACE`
    - :class:`AccessAllowedCallbackObjectACE`
    - :class:`AccessDeniedCallbackObjectACE`

The SACL related ACEs:

    - :class:`SystemAuditACE`
    - :class:`SystemAlarmACE`
    - :class:`SystemAuditObjectACE`
    - :class:`SystemAlarmObjectACE`
    - :class:`SystemAuditCallbackACE`
    - :class:`SystemAlarmCallbackACE`
    - :class:`SystemAuditCallbackObjectACE`
    - :class:`SystemAlarmCallbackObjectACE`
    - :class:`SystemMandatoryLabelACE`
    - :class:`SystemResourceAttributeACE`
    - :class:`SystemScopedPolicyIDACE`
    - :class:`SystemProcessTrustLabelACE`


Ace classes
'''''''''''

AccessAllowedACE
~~~~~~~~~~~~~~~~

.. autoclass:: AccessAllowedACE
    :show-inheritance:
    :inherited-members:

AccessDeniedACE
~~~~~~~~~~~~~~~

.. autoclass:: AccessDeniedACE
    :show-inheritance:
    :inherited-members:


AccessAllowedCallbackACE
~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: AccessAllowedCallbackACE
    :show-inheritance:
    :inherited-members:


AccessDeniedCallbackACE
~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: AccessDeniedCallbackACE
    :show-inheritance:
    :inherited-members:

AccessAllowedObjectACE
~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: AccessAllowedObjectACE
    :show-inheritance:
    :inherited-members:

AccessDeniedObjectACE
~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: AccessDeniedObjectACE
    :show-inheritance:
    :inherited-members:


AccessAllowedCallbackObjectACE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: AccessAllowedCallbackObjectACE
    :show-inheritance:
    :inherited-members:


AccessDeniedCallbackObjectACE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: AccessDeniedCallbackObjectACE
    :show-inheritance:
    :inherited-members:


SystemAuditACE
~~~~~~~~~~~~~~

.. autoclass:: SystemAuditACE
    :show-inheritance:
    :inherited-members:


SystemAlarmACE
~~~~~~~~~~~~~~

.. autoclass:: SystemAlarmACE
    :show-inheritance:
    :inherited-members:

SystemAuditObjectACE
~~~~~~~~~~~~~~~~~~~~

.. autoclass:: SystemAuditObjectACE
    :show-inheritance:
    :inherited-members:

SystemAlarmObjectACE
~~~~~~~~~~~~~~~~~~~~

.. autoclass:: SystemAlarmObjectACE
    :show-inheritance:
    :inherited-members:

SystemAuditCallbackACE
~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: SystemAuditCallbackACE
    :show-inheritance:
    :inherited-members:


SystemAlarmCallbackACE
~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: SystemAlarmCallbackACE
    :show-inheritance:
    :inherited-members:

SystemAuditCallbackObjectACE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: SystemAuditCallbackObjectACE
    :show-inheritance:
    :inherited-members:


SystemAlarmCallbackObjectACE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: SystemAlarmCallbackObjectACE
    :show-inheritance:
    :inherited-members:


SystemMandatoryLabelACE
~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: SystemMandatoryLabelACE
    :show-inheritance:
    :inherited-members:


SystemResourceAttributeACE
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: SystemResourceAttributeACE
    :show-inheritance:
    :inherited-members:


SystemScopedPolicyIDACE
~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: SystemScopedPolicyIDACE
    :show-inheritance:
    :inherited-members:


SystemProcessTrustLabelACE
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: SystemProcessTrustLabelACE
    :show-inheritance:
    :inherited-members:



Ace common base
'''''''''''''''

These classes are internals and here for completness sake.
You should not need to instanciate/use them directly.

AceHeader
~~~~~~~~~

.. autoclass:: AceHeader

AceBase
~~~~~~~

.. autoclass:: AceBase


MaskAndSidACE
~~~~~~~~~~~~~

.. autoclass:: MaskAndSidACE


CallbackACE
~~~~~~~~~~~

.. autoclass:: CallbackACE


ObjectRelatedACE
~~~~~~~~~~~~~~~~

.. autoclass:: ObjectRelatedACE



