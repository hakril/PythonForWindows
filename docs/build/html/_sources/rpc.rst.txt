``windows.rpc`` -- ALPC-based Windows RPC
*****************************************

.. module:: windows.rpc

The :mod:`windows.rpc` allows to perform the basic for MS-RPC:

    * find interface endpoints
    * connect to it
    * bind to interfaces
    * perform call
    * Marshall/Unmarshall NDR

.. note::

    See samples:

        * :ref:`sample_rpc_uac`
        * :ref:`sample_rpc_lsass`


RPCClient
---------

.. autoclass:: RPCClient


Epmapper
--------

.. autoclass:: windows.rpc.epmapper.UnpackTower
    :exclude-members: count, index

:func:`find_alpc_endpoints`
'''''''''''''''''''''''''''

.. autofunction:: find_alpc_endpoints

Example:

.. code-block:: python

    >>> import windows.rpc
    >>> UAC_UIID = "201ef99a-7fa0-444c-9399-19ba84f12a1a"
    >>> windows.rpc.find_alpc_endpoints(UAC_UIID)
    [UnpackTower(protseq='ncalrpc',
                    endpoint=bytearray(b'LRPC-c30c67fef2afa1612b'),
                    address=None,
                    object=<RPC_IF_ID "201EF99A-7FA0-444C-9399-19BA84F12A1A" (1, 0)>,
                    syntax=<RPC_IF_ID "8A885D04-1CEB-11C9-9FE8-08002B104860" (2, 0)>)]


:func:`find_alpc_endpoint_and_connect`
''''''''''''''''''''''''''''''''''''''

.. autofunction:: find_alpc_endpoint_and_connect

Example:

.. code-block:: python

    >>> import windows.rpc
    >>> UAC_UIID = "201ef99a-7fa0-444c-9399-19ba84f12a1a"
    >>> client = windows.rpc.find_alpc_endpoint_and_connect(UAC_UIID)
    >>> client
    <windows.rpc.client.RPCClient object at 0x046A1470>
    >>> client.alpc_client.portname
    '\\RPC Control\\LRPC-c30c67fef2afa1612b'
    >>> iid = client.bind(UAC_UIID)
    >>> iid
    <IID "201EF99A-7FA0-444C-9399-19BA84F12A1A">

Ndr
---

.. module:: windows.rpc.ndr

The :mod:`windows.rpc.ndr` module offers some construction to help marshalling types and structures to NDR.

.. note::

    The NDR supported for now is ``8a885d04-1ceb-11c9-9fe8-08002b104860`` version ``2.0``

Each NDR class has a function :func:`pack`.


.. autoclass:: NdrSID

.. code-block:: python

    >>> import windows.generated_def as gdef
    >>> sid = windows.utils.get_known_sid(gdef.WinLocalSystemSid)
    >>> sid
    c_void_p(78304040)
    >>> psidstr = windows.rpc.ndr.NdrSID.pack(sid)
    >>> psidstr
    '\x01\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00'
    >>> windows.rpc.ndr.NdrSID.unpack(windows.rpc.ndr.NdrStream(psidstr))
    # Implementation is partial for now and does not return a PSID but a string
    '\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00'

.. autoclass:: NdrWString

.. code-block:: python

    >>> from windows.rpc import ndr
    >>> x = ndr.NdrWString.pack("Test-String\x00")
    >>> x
    '\x0c\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00T\x00e\x00s\x00t\x00-\x00S\x00t\x00r\x00i\x00n\x00g\x00\x00\x00'
    >>> ndr.NdrWString.unpack(ndr.NdrStream(x))
    u'Test-String\x00'

.. autoclass:: NdrCString

.. code-block:: python

    >>> from windows.rpc import ndr
    >>> x = ndr.NdrCString.pack("Test-String\x00")
    >>> x
    '\x0c\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00Test-String\x00'
    # TODO: implem unpack

.. autoclass:: NdrLong

.. code-block:: python

    >>> from windows.rpc import ndr
    >>> x = ndr.NdrLong.pack(0x01020304)
    >>> x
    '\x04\x03\x02\x01'
    >>> hex(ndr.NdrLong.unpack(ndr.NdrStream(x)))
    '0x1020304'

.. autoclass:: NdrHyper

.. code-block:: python

    >>> from windows.rpc import ndr
    >>> x = ndr.NdrHyper.pack(0x0102030405060708)
    >>> x
    '\x08\x07\x06\x05\x04\x03\x02\x01'
    >>> hex(ndr.NdrHyper.unpack(ndr.NdrStream(x)))
    '0x102030405060708L'

.. autoclass:: NdrShort

    >>> from windows.rpc import ndr
    >>> x = ndr.NdrShort.pack(0x0102)
    >>> x
    '\x02\x01'
    >>> hex(ndr.NdrShort.unpack(ndr.NdrStream(x)))
    '0x102'

.. autoclass:: NdrByte

.. code-block:: python

    >>> from windows.rpc import ndr
    >>> x = ndr.NdrByte.pack(0x42)
    >>> x
    'B'
    >>> hex(ndr.NdrByte.unpack(ndr.NdrStream(x)))
    '0x42'


.. autoclass:: NdrUniquePTR

.. code-block:: python

    >>> from windows.rpc import ndr
    >>> ndr.NdrLong.pack(0x11111111)
    '\x11\x11\x11\x11'
    >>> ndr.NdrUniquePTR(ndr.NdrLong).pack(0x11111111)
    '\x02\x02\x02\x02\x11\x11\x11\x11'


.. autoclass:: NdrConformantArray
.. autoclass:: NdrConformantVaryingArrays
.. autoclass:: NdrLongConformantArray

.. code-block:: python

    >>> windows.rpc.ndr.NdrLongConformantArray.pack([1,2,3,4])
    '\x04\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00'

.. autoclass:: NdrByteConformantArray

.. code-block:: python

    >>> windows.rpc.ndr.NdrByteConformantArray.pack([1,2,3,4])
    '\x04\x00\x00\x00\x01\x02\x03\x04'


.. autoclass:: NdrStructure

.. code-block:: python

    >>> from windows.rpc import ndr
    >>> class NDRTest(ndr.NdrStructure):
    ...     MEMBERS = [ndr.NdrLong, ndr.NdrLong, ndr.NdrWString]
    ...
    >>> x = NDRTest.pack([1, 2, "Test\x00"])
    >>> x
    '\x01\x00\x00\x00\x02\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00T\x00e\x00s\x00t\x00\x00\x00PP'
    >>> NDRTest.unpack(ndr.NdrStream(x))
    [1, 2, u'Test\x00']


.. autoclass:: NdrParameters


NDR STREAM
''''''''''

.. autoclass:: NdrStream

.. code-block:: python

    >>> from windows.rpc import ndr
    >>> x = ndr.NdrStream("AAAABBBBCCCC")
    >>> hex(ndr.NdrLong.unpack(x))
    '0x41414141'
    >>> x.data
    'BBBBCCCC'
    >>> hex(ndr.NdrShort.unpack(x))
    '0x4242'
    >>> x.data
    'BBCCCC'
    >>> x.align(4)
    >>> x.data
    'CCCC'
    >>> hex(ndr.NdrLong.unpack(x))
    '0x43434343'