.. PyWindows documentation master file, created by
   sphinx-quickstart on Tue Apr 07 11:39:41 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to PythonForWindows's documentation!
============================================

Description
"""""""""""

PythonForWindows is a base of code aimed to make interaction with ``Windows`` (on X86/X64) easier (for both 32 and 64 bits Python).
Its goal is to offer abstractions around some of the OS features in a (I hope) pythonic way.
It also tries to make the barrier between python and native execution thinner in both ways.
There is no external dependencies but it relies heavily on the ``ctypes`` module.

Let's say that the codebase evolves with my needs, my researches and my curiosity.

If you have any issue, question, suggestion do not hesitate to contact me.
I am always glad to have feedbacks from people using this project.

Examples are available on the `github page <https://github.com/hakril/pythonforwindows#pythonforwindows>`_  and in the :ref:`sample_of_code`.


Installation
''''''''''''

Installing from Pypi
^^^^^^^^^^^^^^^^^^^^

PythonForWindows is available on `Pypi <https://pypi.org/project/PythonForWindows/>`_ an this can be installed with::


    python -m pip install PythonForWindows

Installing using setup.py
^^^^^^^^^^^^^^^^^^^^^^^^^


You can also install PythonForWindows by cloning it and using the ``setup.py`` at the root of the project::

    python setup.py install


Encoding & unicode
^^^^^^^^^^^^^^^^^^

PythonForWindows support `python2.7` & `python3` and is currently tested for `Python2.7`, `3.6` & `3.11` via `Github Workflow <https://github.com/hakril/PythonForWindows/actions/workflows/mypytest.yml>`_

Since 1.0.0, the code uses "wide APIs" whenever possible and accept/returns python3 `str` (py2.7 `unicode` type) almost everywhere. Any functions/APIs not accepting unicode string can be  considered a bug if its not stated explicitly in the documentation.


Python2
^^^^^^^

PythonForWindows continues to support python2.7 as its the only way to have it running on `Windows XP` & `Windows Server 2003` which are sadly still seen in production.
Encoding errors at print time might be awkward for unicode string on python2, see the `PythonForWindows encoding guide <https://hakril.github.io/PythonForWindows/build/html/encoding.html>`_ in the documentation.

Documentation
"""""""""""""

.. toctree::
   :maxdepth: 2
   :numbered:

   windows.rst
   winobject.rst
   native_exec.rst
   winproxy.rst
   security.rst
   pipe.rst
   utils.rst
   wintrust.rst
   debug.rst
   com.rst
   crypto.rst
   alpc.rst
   rpc.rst
   generated.rst
   iat_hook.rst
   wip.rst
   internals.rst
   sample.rst
   encoding.rst


Indices and tables
==================

* :ref:`modindex`
* :ref:`search`
* :ref:`genindex`

