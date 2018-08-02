.. module:: windows.generated_def.winstructs

Winstructs
----------
tagMULTI_QI
'''''''''''
.. class:: MULTI_QI

    Alias for :class:`tagMULTI_QI`

.. class:: tagMULTI_QI

    .. attribute:: pIID

        :class:`IID`


    .. attribute:: pItf

        :class:`PVOID`


    .. attribute:: hr

        :class:`HRESULT`

_COAUTHIDENTITY
'''''''''''''''
.. class:: COAUTHIDENTITY

    Alias for :class:`_COAUTHIDENTITY`

.. class:: _COAUTHIDENTITY

    .. attribute:: User

        :class:`USHORT`


    .. attribute:: UserLength

        :class:`ULONG`


    .. attribute:: Domain

        :class:`USHORT`


    .. attribute:: DomainLength

        :class:`ULONG`


    .. attribute:: Password

        :class:`USHORT`


    .. attribute:: PasswordLength

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`

_COAUTHINFO
'''''''''''
.. class:: COAUTHINFO

    Alias for :class:`_COAUTHINFO`

.. class:: _COAUTHINFO

    .. attribute:: dwAuthnSvc

        :class:`DWORD`


    .. attribute:: dwAuthzSvc

        :class:`DWORD`


    .. attribute:: pwszServerPrincName

        :class:`LPWSTR`


    .. attribute:: dwAuthnLevel

        :class:`DWORD`


    .. attribute:: dwImpersonationLevel

        :class:`DWORD`


    .. attribute:: pAuthIdentityData

        :class:`COAUTHIDENTITY`


    .. attribute:: dwCapabilities

        :class:`DWORD`

_COSERVERINFO
'''''''''''''
.. class:: COSERVERINFO

    Alias for :class:`_COSERVERINFO`

.. class:: _COSERVERINFO

    .. attribute:: dwReserved1

        :class:`DWORD`


    .. attribute:: pwszName

        :class:`LPWSTR`


    .. attribute:: pAuthInfo

        :class:`COAUTHINFO`


    .. attribute:: dwReserved2

        :class:`DWORD`

_CALLFRAMEPARAMINFO
'''''''''''''''''''
.. class:: CALLFRAMEPARAMINFO

    Alias for :class:`_CALLFRAMEPARAMINFO`

.. class:: _CALLFRAMEPARAMINFO

    .. attribute:: fIn

        :class:`BOOLEAN`


    .. attribute:: fOut

        :class:`BOOLEAN`


    .. attribute:: stackOffset

        :class:`ULONG`


    .. attribute:: cbParam

        :class:`ULONG`

_CALLFRAMEINFO
''''''''''''''
.. class:: CALLFRAMEINFO

    Alias for :class:`_CALLFRAMEINFO`

.. class:: _CALLFRAMEINFO

    .. attribute:: iMethod

        :class:`ULONG`


    .. attribute:: fHasInValues

        :class:`BOOL`


    .. attribute:: fHasInOutValues

        :class:`BOOL`


    .. attribute:: fHasOutValues

        :class:`BOOL`


    .. attribute:: fDerivesFromIDispatch

        :class:`BOOL`


    .. attribute:: cInInterfacesMax

        :class:`LONG`


    .. attribute:: cInOutInterfacesMax

        :class:`LONG`


    .. attribute:: cOutInterfacesMax

        :class:`LONG`


    .. attribute:: cTopLevelInInterfaces

        :class:`LONG`


    .. attribute:: iid

        :class:`IID`


    .. attribute:: cMethod

        :class:`ULONG`


    .. attribute:: cParams

        :class:`ULONG`

_CALLFRAME_MARSHALCONTEXT
'''''''''''''''''''''''''
.. class:: CALLFRAME_MARSHALCONTEXT

    Alias for :class:`_CALLFRAME_MARSHALCONTEXT`

.. class:: _CALLFRAME_MARSHALCONTEXT

    .. attribute:: fIn

        :class:`BOOLEAN`


    .. attribute:: dwDestContext

        :class:`DWORD`


    .. attribute:: pvDestContext

        :class:`LPVOID`


    .. attribute:: mshlmgr

        :class:`PVOID`


    .. attribute:: guidTransferSyntax

        :class:`GUID`

_FILE_DISPOSITION_INFORMATION
'''''''''''''''''''''''''''''
.. class:: PFILE_DISPOSITION_INFORMATION

    Pointer to :class:`_FILE_DISPOSITION_INFORMATION`

.. class:: FILE_DISPOSITION_INFORMATION

    Alias for :class:`_FILE_DISPOSITION_INFORMATION`

.. class:: _FILE_DISPOSITION_INFORMATION

    .. attribute:: DeleteFile

        :class:`BOOLEAN`

_GUID
'''''
.. class:: REFCLSID

    Pointer to :class:`_GUID`

.. class:: REFGUID

    Pointer to :class:`_GUID`

.. class:: LPGUID

    Pointer to :class:`_GUID`

.. class:: IID

    Alias for :class:`_GUID`

.. class:: CLSID

    Alias for :class:`_GUID`

.. class:: LPCLSID

    Pointer to :class:`_GUID`

.. class:: GUID

    Alias for :class:`_GUID`

.. class:: REFIID

    Pointer to :class:`_GUID`

.. class:: _GUID

    .. attribute:: Data1

        :class:`ULONG`


    .. attribute:: Data2

        :class:`USHORT`


    .. attribute:: Data3

        :class:`USHORT`


    .. attribute:: Data4

        :class:`BYTE` ``[8]``

_ANON_PROCESS_MITIGATION_DEP_POLICY_BITFIELD
''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_DEP_POLICY_BITFIELD

    .. attribute:: Enable

        :class:`DWORD`


    .. attribute:: DisableAtlThunkEmulation

        :class:`DWORD`


    .. attribute:: ReservedFlags

        :class:`DWORD`

_ANON_PROCESS_MITIGATION_DEP_POLICY_UNION
'''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_DEP_POLICY_UNION

    .. attribute:: Flags

        :class:`DWORD`


    .. attribute:: anon

        :class:`_ANON_PROCESS_MITIGATION_DEP_POLICY_BITFIELD`

_PROCESS_MITIGATION_DEP_POLICY
''''''''''''''''''''''''''''''
.. class:: PPROCESS_MITIGATION_DEP_POLICY

    Pointer to :class:`_PROCESS_MITIGATION_DEP_POLICY`

.. class:: PROCESS_MITIGATION_DEP_POLICY

    Alias for :class:`_PROCESS_MITIGATION_DEP_POLICY`

.. class:: _PROCESS_MITIGATION_DEP_POLICY

    .. attribute:: anon

        :class:`_ANON_PROCESS_MITIGATION_DEP_POLICY_UNION`


    .. attribute:: Permanent

        :class:`BOOLEAN`

_ANON_PROCESS_MITIGATION_ASLR_POLICY_BITFIELD
'''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_ASLR_POLICY_BITFIELD

    .. attribute:: EnableBottomUpRandomization

        :class:`DWORD`


    .. attribute:: EnableForceRelocateImages

        :class:`DWORD`


    .. attribute:: EnableHighEntropy

        :class:`DWORD`


    .. attribute:: DisallowStrippedImages

        :class:`DWORD`


    .. attribute:: ReservedFlags

        :class:`DWORD`

_ANON_PROCESS_MITIGATION_ASLR_POLICY_UNION
''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_ASLR_POLICY_UNION

    .. attribute:: Flags

        :class:`DWORD`


    .. attribute:: anon

        :class:`_ANON_PROCESS_MITIGATION_ASLR_POLICY_BITFIELD`

_PROCESS_MITIGATION_ASLR_POLICY
'''''''''''''''''''''''''''''''
.. class:: PPROCESS_MITIGATION_ASLR_POLICY

    Pointer to :class:`_PROCESS_MITIGATION_ASLR_POLICY`

.. class:: PROCESS_MITIGATION_ASLR_POLICY

    Alias for :class:`_PROCESS_MITIGATION_ASLR_POLICY`

.. class:: _PROCESS_MITIGATION_ASLR_POLICY

    .. attribute:: anon

        :class:`_ANON_PROCESS_MITIGATION_ASLR_POLICY_UNION`

_ANON_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_BITFIELD
'''''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_BITFIELD

    .. attribute:: ProhibitDynamicCode

        :class:`DWORD`


    .. attribute:: AllowThreadOptOut

        :class:`DWORD`


    .. attribute:: AllowRemoteDowngrade

        :class:`DWORD`


    .. attribute:: ReservedFlags

        :class:`DWORD`

_ANON_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_UNION
''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_UNION

    .. attribute:: Flags

        :class:`DWORD`


    .. attribute:: anon

        :class:`_ANON_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_BITFIELD`

_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
'''''''''''''''''''''''''''''''''''''''
.. class:: PROCESS_MITIGATION_DYNAMIC_CODE_POLICY

    Alias for :class:`_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY`

.. class:: PPROCESS_MITIGATION_DYNAMIC_CODE_POLICY

    Pointer to :class:`_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY`

.. class:: _PROCESS_MITIGATION_DYNAMIC_CODE_POLICY

    .. attribute:: anon

        :class:`_ANON_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_UNION`

_ANON_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY_BITFIELD
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY_BITFIELD

    .. attribute:: RaiseExceptionOnInvalidHandleReference

        :class:`DWORD`


    .. attribute:: HandleExceptionsPermanentlyEnabled

        :class:`DWORD`


    .. attribute:: ReservedFlags

        :class:`DWORD`

_ANON_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY_UNION
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY_UNION

    .. attribute:: Flags

        :class:`DWORD`


    .. attribute:: ANON_STRUCT

        :class:`_ANON_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY_BITFIELD`

_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY
''''''''''''''''''''''''''''''''''''''''''''''
.. class:: PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY

    Alias for :class:`_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY`

.. class:: PPROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY

    Pointer to :class:`_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY`

.. class:: _PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY

    .. attribute:: anon

        :class:`_ANON_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY_UNION`

_ANON_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_BITFIELD
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_BITFIELD

    .. attribute:: DisallowWin32kSystemCalls

        :class:`DWORD`


    .. attribute:: ReservedFlags

        :class:`DWORD`

_ANON_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_UNION
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_UNION

    .. attribute:: Flags

        :class:`DWORD`


    .. attribute:: ANON_STRUCT

        :class:`_ANON_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_BITFIELD`

_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
''''''''''''''''''''''''''''''''''''''''''''''
.. class:: PPROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY

    Pointer to :class:`_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY`

.. class:: PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY

    Alias for :class:`_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY`

.. class:: _PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY

    .. attribute:: anon

        :class:`_ANON_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_UNION`

_ANON_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_BITFIELD
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_BITFIELD

    .. attribute:: DisableExtensionPoints

        :class:`DWORD`


    .. attribute:: ReservedFlags

        :class:`DWORD`

_ANON_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_UNION
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_UNION

    .. attribute:: Flags

        :class:`DWORD`


    .. attribute:: ANON_STRUCT

        :class:`_ANON_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_BITFIELD`

_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY

    Alias for :class:`_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY`

.. class:: PPROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY

    Pointer to :class:`_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY`

.. class:: _PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY

    .. attribute:: anon

        :class:`_ANON_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_UNION`

_ANON_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_BITFIELD
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_BITFIELD

    .. attribute:: EnableControlFlowGuard

        :class:`DWORD`


    .. attribute:: EnableExportSuppression

        :class:`DWORD`


    .. attribute:: StrictMode

        :class:`DWORD`


    .. attribute:: ReservedFlags

        :class:`DWORD`

_ANON_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_UNION
''''''''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_UNION

    .. attribute:: Flags

        :class:`DWORD`


    .. attribute:: ANON_STRUCT

        :class:`_ANON_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_BITFIELD`

_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY
'''''''''''''''''''''''''''''''''''''''''''''
.. class:: PPROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY

    Pointer to :class:`_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY`

.. class:: PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY

    Alias for :class:`_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY`

.. class:: _PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY

    .. attribute:: anon

        :class:`_ANON_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_UNION`

_ANON_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_BITFIELD
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_BITFIELD

    .. attribute:: MicrosoftSignedOnly

        :class:`DWORD`


    .. attribute:: StoreSignedOnly

        :class:`DWORD`


    .. attribute:: MitigationOptIn

        :class:`DWORD`


    .. attribute:: ReservedFlags

        :class:`DWORD`

_ANON_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_UNION
''''''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_UNION

    .. attribute:: Flags

        :class:`DWORD`


    .. attribute:: ANON_STRUCT

        :class:`_ANON_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_BITFIELD`

_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
'''''''''''''''''''''''''''''''''''''''''''
.. class:: PPROCESS_MITIGATION_BINARY_SIGNATURE_POLICY

    Pointer to :class:`_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY`

.. class:: PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY

    Alias for :class:`_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY`

.. class:: _PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY

    .. attribute:: anon

        :class:`_ANON_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_UNION`

_ANON_PROCESS_MITIGATION_IMAGE_LOAD_POLICY_BITFIELD
'''''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_IMAGE_LOAD_POLICY_BITFIELD

    .. attribute:: NoRemoteImages

        :class:`DWORD`


    .. attribute:: NoLowMandatoryLabelImages

        :class:`DWORD`


    .. attribute:: PreferSystem32Images

        :class:`DWORD`


    .. attribute:: ReservedFlags

        :class:`DWORD`

_ANON_PROCESS_MITIGATION_IMAGE_LOAD_POLICY_UNION
''''''''''''''''''''''''''''''''''''''''''''''''
.. class:: _ANON_PROCESS_MITIGATION_IMAGE_LOAD_POLICY_UNION

    .. attribute:: Flags

        :class:`DWORD`


    .. attribute:: ANON_STRUCT

        :class:`_ANON_PROCESS_MITIGATION_IMAGE_LOAD_POLICY_BITFIELD`

_PROCESS_MITIGATION_IMAGE_LOAD_POLICY
'''''''''''''''''''''''''''''''''''''
.. class:: PPROCESS_MITIGATION_IMAGE_LOAD_POLICY

    Pointer to :class:`_PROCESS_MITIGATION_IMAGE_LOAD_POLICY`

.. class:: PROCESS_MITIGATION_IMAGE_LOAD_POLICY

    Alias for :class:`_PROCESS_MITIGATION_IMAGE_LOAD_POLICY`

.. class:: _PROCESS_MITIGATION_IMAGE_LOAD_POLICY

    .. attribute:: anon

        :class:`_ANON_PROCESS_MITIGATION_IMAGE_LOAD_POLICY_UNION`

_KEY_VALUE_BASIC_INFORMATION
''''''''''''''''''''''''''''
.. class:: PKEY_VALUE_BASIC_INFORMATION

    Pointer to :class:`_KEY_VALUE_BASIC_INFORMATION`

.. class:: KEY_VALUE_BASIC_INFORMATION

    Alias for :class:`_KEY_VALUE_BASIC_INFORMATION`

.. class:: _KEY_VALUE_BASIC_INFORMATION

    .. attribute:: TitleIndex

        :class:`ULONG`


    .. attribute:: Type

        :class:`ULONG`


    .. attribute:: NameLength

        :class:`ULONG`


    .. attribute:: Name

        :class:`WCHAR` ``[1]``

_KEY_VALUE_FULL_INFORMATION
'''''''''''''''''''''''''''
.. class:: KEY_VALUE_FULL_INFORMATION

    Alias for :class:`_KEY_VALUE_FULL_INFORMATION`

.. class:: PKEY_VALUE_FULL_INFORMATION

    Pointer to :class:`_KEY_VALUE_FULL_INFORMATION`

.. class:: _KEY_VALUE_FULL_INFORMATION

    .. attribute:: TitleIndex

        :class:`ULONG`


    .. attribute:: Type

        :class:`ULONG`


    .. attribute:: DataOffset

        :class:`ULONG`


    .. attribute:: DataLength

        :class:`ULONG`


    .. attribute:: NameLength

        :class:`ULONG`


    .. attribute:: Name

        :class:`WCHAR` ``[1]``

_KEY_VALUE_PARTIAL_INFORMATION
''''''''''''''''''''''''''''''
.. class:: PKEY_VALUE_PARTIAL_INFORMATION

    Pointer to :class:`_KEY_VALUE_PARTIAL_INFORMATION`

.. class:: KEY_VALUE_PARTIAL_INFORMATION

    Alias for :class:`_KEY_VALUE_PARTIAL_INFORMATION`

.. class:: _KEY_VALUE_PARTIAL_INFORMATION

    .. attribute:: TitleIndex

        :class:`ULONG`


    .. attribute:: Type

        :class:`ULONG`


    .. attribute:: DataLength

        :class:`ULONG`


    .. attribute:: Data

        :class:`UCHAR` ``[1]``

_SHITEMID
'''''''''
.. class:: SHITEMID

    Alias for :class:`_SHITEMID`

.. class:: _SHITEMID

    .. attribute:: cb

        :class:`USHORT`


    .. attribute:: abID

        :class:`BYTE` ``[1]``

_ITEMIDLIST
'''''''''''
.. class:: ITEMIDLIST

    Alias for :class:`_ITEMIDLIST`

.. class:: PCIDLIST_ABSOLUTE

    Pointer to :class:`_ITEMIDLIST`

.. class:: PIDLIST_ABSOLUTE

    Pointer to :class:`_ITEMIDLIST`

.. class:: _ITEMIDLIST

    .. attribute:: mkid

        :class:`SHITEMID`

tagRGBTRIPLE
''''''''''''
.. class:: NPRGBTRIPLE

    Pointer to :class:`tagRGBTRIPLE`

.. class:: LPRGBTRIPLE

    Pointer to :class:`tagRGBTRIPLE`

.. class:: RGBTRIPLE

    Alias for :class:`tagRGBTRIPLE`

.. class:: PRGBTRIPLE

    Pointer to :class:`tagRGBTRIPLE`

.. class:: tagRGBTRIPLE

    .. attribute:: rgbtBlue

        :class:`BYTE`


    .. attribute:: rgbtGreen

        :class:`BYTE`


    .. attribute:: rgbtRed

        :class:`BYTE`

tagBITMAPFILEHEADER
'''''''''''''''''''
.. class:: BITMAPFILEHEADER

    Alias for :class:`tagBITMAPFILEHEADER`

.. class:: PBITMAPFILEHEADER

    Pointer to :class:`tagBITMAPFILEHEADER`

.. class:: LPBITMAPFILEHEADER

    Pointer to :class:`tagBITMAPFILEHEADER`

.. class:: tagBITMAPFILEHEADER

    .. attribute:: bfType

        :class:`WORD`


    .. attribute:: bfSize

        :class:`DWORD`


    .. attribute:: bfReserved1

        :class:`WORD`


    .. attribute:: bfReserved2

        :class:`WORD`


    .. attribute:: bfOffBits

        :class:`DWORD`

tagBITMAPCOREHEADER
'''''''''''''''''''
.. class:: LPBITMAPCOREHEADER

    Pointer to :class:`tagBITMAPCOREHEADER`

.. class:: PBITMAPCOREHEADER

    Pointer to :class:`tagBITMAPCOREHEADER`

.. class:: BITMAPCOREHEADER

    Alias for :class:`tagBITMAPCOREHEADER`

.. class:: tagBITMAPCOREHEADER

    .. attribute:: bcSize

        :class:`DWORD`


    .. attribute:: bcWidth

        :class:`WORD`


    .. attribute:: bcHeight

        :class:`WORD`


    .. attribute:: bcPlanes

        :class:`WORD`


    .. attribute:: bcBitCount

        :class:`WORD`

tagBITMAP
'''''''''
.. class:: NPBITMAP

    Pointer to :class:`tagBITMAP`

.. class:: LPBITMAP

    Pointer to :class:`tagBITMAP`

.. class:: PBITMAP

    Pointer to :class:`tagBITMAP`

.. class:: BITMAP

    Alias for :class:`tagBITMAP`

.. class:: tagBITMAP

    .. attribute:: bmType

        :class:`LONG`


    .. attribute:: bmWidth

        :class:`LONG`


    .. attribute:: bmHeight

        :class:`LONG`


    .. attribute:: bmWidthBytes

        :class:`LONG`


    .. attribute:: bmPlanes

        :class:`WORD`


    .. attribute:: bmBitsPixel

        :class:`WORD`


    .. attribute:: bmBits

        :class:`LPVOID`

tagBITMAPINFOHEADER
'''''''''''''''''''
.. class:: BITMAPINFOHEADER

    Alias for :class:`tagBITMAPINFOHEADER`

.. class:: PBITMAPINFOHEADER

    Pointer to :class:`tagBITMAPINFOHEADER`

.. class:: LPBITMAPINFOHEADER

    Pointer to :class:`tagBITMAPINFOHEADER`

.. class:: tagBITMAPINFOHEADER

    .. attribute:: biSize

        :class:`DWORD`


    .. attribute:: biWidth

        :class:`LONG`


    .. attribute:: biHeight

        :class:`LONG`


    .. attribute:: biPlanes

        :class:`WORD`


    .. attribute:: biBitCount

        :class:`WORD`


    .. attribute:: biCompression

        :class:`DWORD`


    .. attribute:: biSizeImage

        :class:`DWORD`


    .. attribute:: biXPelsPerMeter

        :class:`LONG`


    .. attribute:: biYPelsPerMeter

        :class:`LONG`


    .. attribute:: biClrUsed

        :class:`DWORD`


    .. attribute:: biClrImportant

        :class:`DWORD`

tagRGBQUAD
''''''''''
.. class:: RGBQUAD

    Alias for :class:`tagRGBQUAD`

.. class:: tagRGBQUAD

    .. attribute:: rgbBlue

        :class:`BYTE`


    .. attribute:: rgbGreen

        :class:`BYTE`


    .. attribute:: rgbRed

        :class:`BYTE`


    .. attribute:: rgbReserved

        :class:`BYTE`

tagBITMAPINFO
'''''''''''''
.. class:: LPBITMAPINFO

    Pointer to :class:`tagBITMAPINFO`

.. class:: PBITMAPINFO

    Pointer to :class:`tagBITMAPINFO`

.. class:: BITMAPINFO

    Alias for :class:`tagBITMAPINFO`

.. class:: tagBITMAPINFO

    .. attribute:: bmiHeader

        :class:`BITMAPINFOHEADER`


    .. attribute:: bmiColors

        :class:`RGBQUAD` ``[1]``

tagBITMAPCOREINFO
'''''''''''''''''
.. class:: LPBITMAPCOREINFO

    Pointer to :class:`tagBITMAPCOREINFO`

.. class:: BITMAPCOREINFO

    Alias for :class:`tagBITMAPCOREINFO`

.. class:: PBITMAPCOREINFO

    Pointer to :class:`tagBITMAPCOREINFO`

.. class:: tagBITMAPCOREINFO

    .. attribute:: bmciHeader

        :class:`BITMAPCOREHEADER`


    .. attribute:: bmciColors

        :class:`RGBTRIPLE` ``[1]``

tagWNDCLASSEXA
''''''''''''''
.. class:: PWNDCLASSEXA

    Pointer to :class:`tagWNDCLASSEXA`

.. class:: LPWNDCLASSEXA

    Pointer to :class:`tagWNDCLASSEXA`

.. class:: WNDCLASSEXA

    Alias for :class:`tagWNDCLASSEXA`

.. class:: tagWNDCLASSEXA

    .. attribute:: cbSize

        :class:`UINT`


    .. attribute:: style

        :class:`UINT`


    .. attribute:: lpfnWndProc

        :class:`WNDPROC`


    .. attribute:: cbClsExtra

        :class:`INT`


    .. attribute:: cbWndExtra

        :class:`INT`


    .. attribute:: hInstance

        :class:`HINSTANCE`


    .. attribute:: hIcon

        :class:`HICON`


    .. attribute:: hCursor

        :class:`HCURSOR`


    .. attribute:: hbrBackground

        :class:`HBRUSH`


    .. attribute:: lpszMenuName

        :class:`LPCSTR`


    .. attribute:: lpszClassName

        :class:`LPCSTR`


    .. attribute:: hIconSm

        :class:`HICON`

tagWNDCLASSEXW
''''''''''''''
.. class:: WNDCLASSEXW

    Alias for :class:`tagWNDCLASSEXW`

.. class:: LPWNDCLASSEXW

    Pointer to :class:`tagWNDCLASSEXW`

.. class:: PWNDCLASSEXW

    Pointer to :class:`tagWNDCLASSEXW`

.. class:: tagWNDCLASSEXW

    .. attribute:: cbSize

        :class:`UINT`


    .. attribute:: style

        :class:`UINT`


    .. attribute:: lpfnWndProc

        :class:`WNDPROC`


    .. attribute:: cbClsExtra

        :class:`INT`


    .. attribute:: cbWndExtra

        :class:`INT`


    .. attribute:: hInstance

        :class:`HINSTANCE`


    .. attribute:: hIcon

        :class:`HICON`


    .. attribute:: hCursor

        :class:`HCURSOR`


    .. attribute:: hbrBackground

        :class:`HBRUSH`


    .. attribute:: lpszMenuName

        :class:`LPWSTR`


    .. attribute:: lpszClassName

        :class:`LPWSTR`


    .. attribute:: hIconSm

        :class:`HICON`

_LIST_ENTRY
'''''''''''
.. class:: PLIST_ENTRY

    Pointer to :class:`_LIST_ENTRY`

.. class:: LIST_ENTRY

    Alias for :class:`_LIST_ENTRY`

.. class:: PRLIST_ENTRY

    Pointer to :class:`_LIST_ENTRY`

.. class:: _LIST_ENTRY

    .. attribute:: Flink

        :class:`_LIST_ENTRY`


    .. attribute:: Blink

        :class:`_LIST_ENTRY`

_PEB_LDR_DATA
'''''''''''''
.. class:: PPEB_LDR_DATA

    Pointer to :class:`_PEB_LDR_DATA`

.. class:: PEB_LDR_DATA

    Alias for :class:`_PEB_LDR_DATA`

.. class:: _PEB_LDR_DATA

    .. attribute:: Reserved1

        :class:`BYTE` ``[8]``


    .. attribute:: Reserved2

        :class:`PVOID` ``[3]``


    .. attribute:: InMemoryOrderModuleList

        :class:`LIST_ENTRY`

_LSA_UNICODE_STRING
'''''''''''''''''''
.. class:: PUNICODE_STRING

    Pointer to :class:`_LSA_UNICODE_STRING`

.. class:: UNICODE_STRING

    Alias for :class:`_LSA_UNICODE_STRING`

.. class:: LSA_UNICODE_STRING

    Alias for :class:`_LSA_UNICODE_STRING`

.. class:: PLSA_UNICODE_STRING

    Pointer to :class:`_LSA_UNICODE_STRING`

.. class:: _LSA_UNICODE_STRING

    .. attribute:: Length

        :class:`USHORT`


    .. attribute:: MaximumLength

        :class:`USHORT`


    .. attribute:: Buffer

        :class:`PVOID`

_CURDIR
'''''''
.. class:: PCURDIR

    Pointer to :class:`_CURDIR`

.. class:: CURDIR

    Alias for :class:`_CURDIR`

.. class:: _CURDIR

    .. attribute:: DosPath

        :class:`UNICODE_STRING`


    .. attribute:: Handle

        :class:`PVOID`

_RTL_DRIVE_LETTER_CURDIR
''''''''''''''''''''''''
.. class:: PRTL_DRIVE_LETTER_CURDIR

    Pointer to :class:`_RTL_DRIVE_LETTER_CURDIR`

.. class:: RTL_DRIVE_LETTER_CURDIR

    Alias for :class:`_RTL_DRIVE_LETTER_CURDIR`

.. class:: _RTL_DRIVE_LETTER_CURDIR

    .. attribute:: Flags

        :class:`WORD`


    .. attribute:: Length

        :class:`WORD`


    .. attribute:: TimeStamp

        :class:`ULONG`


    .. attribute:: DosPath

        :class:`UNICODE_STRING`

_RTL_USER_PROCESS_PARAMETERS
''''''''''''''''''''''''''''
.. class:: PRTL_USER_PROCESS_PARAMETERS

    Pointer to :class:`_RTL_USER_PROCESS_PARAMETERS`

.. class:: RTL_USER_PROCESS_PARAMETERS

    Alias for :class:`_RTL_USER_PROCESS_PARAMETERS`

.. class:: _RTL_USER_PROCESS_PARAMETERS

    .. attribute:: MaximumLength

        :class:`ULONG`


    .. attribute:: Length

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: DebugFlags

        :class:`ULONG`


    .. attribute:: ConsoleHandle

        :class:`PVOID`


    .. attribute:: ConsoleFlags

        :class:`ULONG`


    .. attribute:: StandardInput

        :class:`PVOID`


    .. attribute:: StandardOutput

        :class:`PVOID`


    .. attribute:: StandardError

        :class:`PVOID`


    .. attribute:: CurrentDirectory

        :class:`CURDIR`


    .. attribute:: DllPath

        :class:`UNICODE_STRING`


    .. attribute:: ImagePathName

        :class:`UNICODE_STRING`


    .. attribute:: CommandLine

        :class:`UNICODE_STRING`


    .. attribute:: Environment

        :class:`PVOID`


    .. attribute:: StartingX

        :class:`ULONG`


    .. attribute:: StartingY

        :class:`ULONG`


    .. attribute:: CountX

        :class:`ULONG`


    .. attribute:: CountY

        :class:`ULONG`


    .. attribute:: CountCharsX

        :class:`ULONG`


    .. attribute:: CountCharsY

        :class:`ULONG`


    .. attribute:: FillAttribute

        :class:`ULONG`


    .. attribute:: WindowFlags

        :class:`ULONG`


    .. attribute:: ShowWindowFlags

        :class:`ULONG`


    .. attribute:: WindowTitle

        :class:`UNICODE_STRING`


    .. attribute:: DesktopInfo

        :class:`UNICODE_STRING`


    .. attribute:: ShellInfo

        :class:`UNICODE_STRING`


    .. attribute:: RuntimeData

        :class:`UNICODE_STRING`


    .. attribute:: CurrentDirectores

        :class:`RTL_DRIVE_LETTER_CURDIR` ``[32]``

_ANON_PEB_SYSTEM_DEPENDENT_02
'''''''''''''''''''''''''''''
.. class:: _ANON_PEB_SYSTEM_DEPENDENT_02

    .. attribute:: FastPebLockRoutine

        :class:`PVOID`


    .. attribute:: SparePtr1

        :class:`PVOID`


    .. attribute:: AtlThunkSListPtr

        :class:`PVOID`

_ANON_PEB_SYSTEM_DEPENDENT_03
'''''''''''''''''''''''''''''
.. class:: _ANON_PEB_SYSTEM_DEPENDENT_03

    .. attribute:: FastPebUnlockRoutine

        :class:`PVOID`


    .. attribute:: SparePtr2

        :class:`PVOID`


    .. attribute:: IFEOKey

        :class:`PVOID`

_ANON_PEB_SYSTEM_DEPENDENT_06
'''''''''''''''''''''''''''''
.. class:: _ANON_PEB_SYSTEM_DEPENDENT_06

    .. attribute:: FreeList

        :class:`PVOID`


    .. attribute:: SparePebPtr0

        :class:`PVOID`


    .. attribute:: ApiSetMap

        :class:`PVOID`

_ANON_PEB_SYSTEM_DEPENDENT_07
'''''''''''''''''''''''''''''
.. class:: _ANON_PEB_SYSTEM_DEPENDENT_07

    .. attribute:: ReadOnlySharedMemoryHeap

        :class:`PVOID`


    .. attribute:: HotpatchInformation

        :class:`PVOID`


    .. attribute:: SparePvoid0

        :class:`PVOID`

_ANON_PEB_UNION_1
'''''''''''''''''
.. class:: _ANON_PEB_UNION_1

    .. attribute:: KernelCallbackTable

        :class:`PVOID`


    .. attribute:: UserSharedInfoPtr

        :class:`PVOID`

_ANON_PEB_UNION_2
'''''''''''''''''
.. class:: _ANON_PEB_UNION_2

    .. attribute:: ImageProcessAffinityMask

        :class:`PVOID`


    .. attribute:: ActiveProcessAffinityMask

        :class:`PVOID`

_PEB
''''
.. class:: PPEB

    Pointer to :class:`_PEB`

.. class:: PEB

    Alias for :class:`_PEB`

.. class:: _PEB

    .. attribute:: Reserved1

        :class:`BYTE` ``[2]``


    .. attribute:: BeingDebugged

        :class:`BYTE`


    .. attribute:: Reserved2

        :class:`BYTE` ``[1]``


    .. attribute:: Mutant

        :class:`PVOID`


    .. attribute:: ImageBaseAddress

        :class:`PVOID`


    .. attribute:: Ldr

        :class:`PPEB_LDR_DATA`


    .. attribute:: ProcessParameters

        :class:`PRTL_USER_PROCESS_PARAMETERS`


    .. attribute:: SubSystemData

        :class:`PVOID`


    .. attribute:: ProcessHeap

        :class:`PVOID`


    .. attribute:: FastPebLock

        :class:`PVOID`


    .. attribute:: _SYSTEM_DEPENDENT_02

        :class:`_ANON_PEB_SYSTEM_DEPENDENT_02`


    .. attribute:: _SYSTEM_DEPENDENT_03

        :class:`_ANON_PEB_SYSTEM_DEPENDENT_03`


    .. attribute:: _SYSTEM_DEPENDENT_04

        :class:`PVOID`


    .. attribute:: anon_union_1

        :class:`_ANON_PEB_UNION_1`


    .. attribute:: SystemReserved

        :class:`DWORD`


    .. attribute:: _SYSTEM_DEPENDENT_05

        :class:`DWORD`


    .. attribute:: _SYSTEM_DEPENDENT_06

        :class:`_ANON_PEB_SYSTEM_DEPENDENT_06`


    .. attribute:: TlsExpansionCounter

        :class:`PVOID`


    .. attribute:: TlsBitmap

        :class:`PVOID`


    .. attribute:: TlsBitmapBits

        :class:`DWORD` ``[2]``


    .. attribute:: ReadOnlySharedMemoryBase

        :class:`PVOID`


    .. attribute:: _SYSTEM_DEPENDENT_07

        :class:`_ANON_PEB_SYSTEM_DEPENDENT_07`


    .. attribute:: ReadOnlyStaticServerData

        :class:`PVOID`


    .. attribute:: AnsiCodePageData

        :class:`PVOID`


    .. attribute:: OemCodePageData

        :class:`PVOID`


    .. attribute:: UnicodeCaseTableData

        :class:`PVOID`


    .. attribute:: NumberOfProcessors

        :class:`DWORD`


    .. attribute:: NtGlobalFlag

        :class:`DWORD`


    .. attribute:: CriticalSectionTimeout

        :class:`LARGE_INTEGER`


    .. attribute:: HeapSegmentReserve

        :class:`PVOID`


    .. attribute:: HeapSegmentCommit

        :class:`PVOID`


    .. attribute:: HeapDeCommitTotalFreeThreshold

        :class:`PVOID`


    .. attribute:: HeapDeCommitFreeBlockThreshold

        :class:`PVOID`


    .. attribute:: NumberOfHeaps

        :class:`DWORD`


    .. attribute:: MaximumNumberOfHeaps

        :class:`DWORD`


    .. attribute:: ProcessHeaps

        :class:`PVOID`


    .. attribute:: GdiSharedHandleTable

        :class:`PVOID`


    .. attribute:: ProcessStarterHelper

        :class:`PVOID`


    .. attribute:: GdiDCAttributeList

        :class:`PVOID`


    .. attribute:: LoaderLock

        :class:`PVOID`


    .. attribute:: OSMajorVersion

        :class:`DWORD`


    .. attribute:: OSMinorVersion

        :class:`DWORD`


    .. attribute:: OSBuildNumber

        :class:`WORD`


    .. attribute:: OSCSDVersion

        :class:`WORD`


    .. attribute:: OSPlatformId

        :class:`DWORD`


    .. attribute:: ImageSubsystem

        :class:`DWORD`


    .. attribute:: ImageSubsystemMajorVersion

        :class:`DWORD`


    .. attribute:: ImageSubsystemMinorVersion

        :class:`PVOID`


    .. attribute:: anon_union_2

        :class:`_ANON_PEB_UNION_2`


    .. attribute:: GdiHandleBuffer

        :class:`PVOID` ``[26]``


    .. attribute:: GdiHandleBuffer2

        :class:`BYTE` ``[32]``


    .. attribute:: PostProcessInitRoutine

        :class:`PVOID`


    .. attribute:: TlsExpansionBitmap

        :class:`PVOID`


    .. attribute:: TlsExpansionBitmapBits

        :class:`DWORD` ``[32]``


    .. attribute:: SessionId

        :class:`PVOID`


    .. attribute:: AppCompatFlags

        :class:`ULARGE_INTEGER`


    .. attribute:: AppCompatFlagsUser

        :class:`ULARGE_INTEGER`


    .. attribute:: pShimData

        :class:`PVOID`


    .. attribute:: AppCompatInfo

        :class:`PVOID`


    .. attribute:: CSDVersion

        :class:`UNICODE_STRING`


    .. attribute:: ActivationContextData

        :class:`PVOID`


    .. attribute:: ProcessAssemblyStorageMap

        :class:`PVOID`


    .. attribute:: SystemDefaultActivationContextData

        :class:`PVOID`


    .. attribute:: SystemAssemblyStorageMap

        :class:`PVOID`


    .. attribute:: MinimumStackCommit

        :class:`PVOID`

_SECURITY_ATTRIBUTES
''''''''''''''''''''
.. class:: SECURITY_ATTRIBUTES

    Alias for :class:`_SECURITY_ATTRIBUTES`

.. class:: LPSECURITY_ATTRIBUTES

    Pointer to :class:`_SECURITY_ATTRIBUTES`

.. class:: PSECURITY_ATTRIBUTES

    Pointer to :class:`_SECURITY_ATTRIBUTES`

.. class:: _SECURITY_ATTRIBUTES

    .. attribute:: nLength

        :class:`DWORD`


    .. attribute:: lpSecurityDescriptor

        :class:`LPVOID`


    .. attribute:: bInheritHandle

        :class:`BOOL`

_SYSTEM_VERIFIER_INFORMATION
''''''''''''''''''''''''''''
.. class:: PSYSTEM_VERIFIER_INFORMATION

    Pointer to :class:`_SYSTEM_VERIFIER_INFORMATION`

.. class:: SYSTEM_VERIFIER_INFORMATION

    Alias for :class:`_SYSTEM_VERIFIER_INFORMATION`

.. class:: _SYSTEM_VERIFIER_INFORMATION

    .. attribute:: NextEntryOffset

        :class:`ULONG`


    .. attribute:: Level

        :class:`ULONG`


    .. attribute:: DriverName

        :class:`UNICODE_STRING`


    .. attribute:: RaiseIrqls

        :class:`ULONG`


    .. attribute:: AcquireSpinLocks

        :class:`ULONG`


    .. attribute:: SynchronizeExecutions

        :class:`ULONG`


    .. attribute:: AllocationsAttempted

        :class:`ULONG`


    .. attribute:: AllocationsSucceeded

        :class:`ULONG`


    .. attribute:: AllocationsSucceededSpecialPool

        :class:`ULONG`


    .. attribute:: AllocationsWithNoTag

        :class:`ULONG`


    .. attribute:: TrimRequests

        :class:`ULONG`


    .. attribute:: Trims

        :class:`ULONG`


    .. attribute:: AllocationsFailed

        :class:`ULONG`


    .. attribute:: AllocationsFailedDeliberately

        :class:`ULONG`


    .. attribute:: Loads

        :class:`ULONG`


    .. attribute:: Unloads

        :class:`ULONG`


    .. attribute:: UnTrackedPool

        :class:`ULONG`


    .. attribute:: CurrentPagedPoolAllocations

        :class:`ULONG`


    .. attribute:: CurrentNonPagedPoolAllocations

        :class:`ULONG`


    .. attribute:: PeakPagedPoolAllocations

        :class:`ULONG`


    .. attribute:: PeakNonPagedPoolAllocations

        :class:`ULONG`


    .. attribute:: PagedPoolUsageInBytes

        :class:`SIZE_T`


    .. attribute:: NonPagedPoolUsageInBytes

        :class:`SIZE_T`


    .. attribute:: PeakPagedPoolUsageInBytes

        :class:`SIZE_T`


    .. attribute:: PeakNonPagedPoolUsageInBytes

        :class:`SIZE_T`

_CLIENT_ID
''''''''''
.. class:: CLIENT_ID

    Alias for :class:`_CLIENT_ID`

.. class:: _CLIENT_ID

    .. attribute:: UniqueProcess

        :class:`HANDLE`


    .. attribute:: UniqueThread

        :class:`HANDLE`

_CLIENT_ID64
''''''''''''
.. class:: CLIENT_ID64

    Alias for :class:`_CLIENT_ID64`

.. class:: _CLIENT_ID64

    .. attribute:: UniqueProcess

        :class:`ULONG64`


    .. attribute:: UniqueThread

        :class:`ULONG64`

_CLIENT_ID32
''''''''''''
.. class:: CLIENT_ID32

    Alias for :class:`_CLIENT_ID32`

.. class:: _CLIENT_ID32

    .. attribute:: UniqueProcess

        :class:`ULONG`


    .. attribute:: UniqueThread

        :class:`ULONG`

_LDR_DATA_TABLE_ENTRY
'''''''''''''''''''''
.. class:: PLDR_DATA_TABLE_ENTRY

    Pointer to :class:`_LDR_DATA_TABLE_ENTRY`

.. class:: LDR_DATA_TABLE_ENTRY

    Alias for :class:`_LDR_DATA_TABLE_ENTRY`

.. class:: _LDR_DATA_TABLE_ENTRY

    .. attribute:: Reserved1

        :class:`PVOID` ``[2]``


    .. attribute:: InMemoryOrderLinks

        :class:`LIST_ENTRY`


    .. attribute:: Reserved2

        :class:`PVOID` ``[2]``


    .. attribute:: DllBase

        :class:`PVOID`


    .. attribute:: EntryPoint

        :class:`PVOID`


    .. attribute:: SizeOfImage

        :class:`PVOID`


    .. attribute:: FullDllName

        :class:`UNICODE_STRING`


    .. attribute:: BaseDllName

        :class:`UNICODE_STRING`


    .. attribute:: Reserved5

        :class:`PVOID` ``[3]``


    .. attribute:: CheckSum

        :class:`ULONG`


    .. attribute:: TimeDateStamp

        :class:`ULONG`

_IMAGE_FILE_HEADER
''''''''''''''''''
.. class:: IMAGE_FILE_HEADER

    Alias for :class:`_IMAGE_FILE_HEADER`

.. class:: PIMAGE_FILE_HEADER

    Pointer to :class:`_IMAGE_FILE_HEADER`

.. class:: _IMAGE_FILE_HEADER

    .. attribute:: Machine

        :class:`WORD`


    .. attribute:: NumberOfSections

        :class:`WORD`


    .. attribute:: TimeDateStamp

        :class:`DWORD`


    .. attribute:: PointerToSymbolTable

        :class:`DWORD`


    .. attribute:: NumberOfSymbols

        :class:`DWORD`


    .. attribute:: SizeOfOptionalHeader

        :class:`WORD`


    .. attribute:: Characteristics

        :class:`WORD`

_IMAGE_DATA_DIRECTORY
'''''''''''''''''''''
.. class:: IMAGE_DATA_DIRECTORY

    Alias for :class:`_IMAGE_DATA_DIRECTORY`

.. class:: PIMAGE_DATA_DIRECTORY

    Pointer to :class:`_IMAGE_DATA_DIRECTORY`

.. class:: _IMAGE_DATA_DIRECTORY

    .. attribute:: VirtualAddress

        :class:`DWORD`


    .. attribute:: Size

        :class:`DWORD`

_IMAGE_SECTION_HEADER
'''''''''''''''''''''
.. class:: PIMAGE_SECTION_HEADER

    Pointer to :class:`_IMAGE_SECTION_HEADER`

.. class:: IMAGE_SECTION_HEADER

    Alias for :class:`_IMAGE_SECTION_HEADER`

.. class:: _IMAGE_SECTION_HEADER

    .. attribute:: Name

        :class:`BYTE` ``[IMAGE_SIZEOF_SHORT_NAME]``


    .. attribute:: VirtualSize

        :class:`DWORD`


    .. attribute:: VirtualAddress

        :class:`DWORD`


    .. attribute:: SizeOfRawData

        :class:`DWORD`


    .. attribute:: PointerToRawData

        :class:`DWORD`


    .. attribute:: PointerToRelocations

        :class:`DWORD`


    .. attribute:: PointerToLinenumbers

        :class:`DWORD`


    .. attribute:: NumberOfRelocations

        :class:`WORD`


    .. attribute:: NumberOfLinenumbers

        :class:`WORD`


    .. attribute:: Characteristics

        :class:`DWORD`

_IMAGE_OPTIONAL_HEADER64
''''''''''''''''''''''''
.. class:: PIMAGE_OPTIONAL_HEADER64

    Pointer to :class:`_IMAGE_OPTIONAL_HEADER64`

.. class:: IMAGE_OPTIONAL_HEADER64

    Alias for :class:`_IMAGE_OPTIONAL_HEADER64`

.. class:: _IMAGE_OPTIONAL_HEADER64

    .. attribute:: Magic

        :class:`WORD`


    .. attribute:: MajorLinkerVersion

        :class:`BYTE`


    .. attribute:: MinorLinkerVersion

        :class:`BYTE`


    .. attribute:: SizeOfCode

        :class:`DWORD`


    .. attribute:: SizeOfInitializedData

        :class:`DWORD`


    .. attribute:: SizeOfUninitializedData

        :class:`DWORD`


    .. attribute:: AddressOfEntryPoint

        :class:`DWORD`


    .. attribute:: BaseOfCode

        :class:`DWORD`


    .. attribute:: ImageBase

        :class:`ULONGLONG`


    .. attribute:: SectionAlignment

        :class:`DWORD`


    .. attribute:: FileAlignment

        :class:`DWORD`


    .. attribute:: MajorOperatingSystemVersion

        :class:`WORD`


    .. attribute:: MinorOperatingSystemVersion

        :class:`WORD`


    .. attribute:: MajorImageVersion

        :class:`WORD`


    .. attribute:: MinorImageVersion

        :class:`WORD`


    .. attribute:: MajorSubsystemVersion

        :class:`WORD`


    .. attribute:: MinorSubsystemVersion

        :class:`WORD`


    .. attribute:: Win32VersionValue

        :class:`DWORD`


    .. attribute:: SizeOfImage

        :class:`DWORD`


    .. attribute:: SizeOfHeaders

        :class:`DWORD`


    .. attribute:: CheckSum

        :class:`DWORD`


    .. attribute:: Subsystem

        :class:`WORD`


    .. attribute:: DllCharacteristics

        :class:`WORD`


    .. attribute:: SizeOfStackReserve

        :class:`ULONGLONG`


    .. attribute:: SizeOfStackCommit

        :class:`ULONGLONG`


    .. attribute:: SizeOfHeapReserve

        :class:`ULONGLONG`


    .. attribute:: SizeOfHeapCommit

        :class:`ULONGLONG`


    .. attribute:: LoaderFlags

        :class:`DWORD`


    .. attribute:: NumberOfRvaAndSizes

        :class:`DWORD`


    .. attribute:: DataDirectory

        :class:`IMAGE_DATA_DIRECTORY` ``[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]``

_IMAGE_OPTIONAL_HEADER
''''''''''''''''''''''
.. class:: PIMAGE_OPTIONAL_HEADER32

    Pointer to :class:`_IMAGE_OPTIONAL_HEADER`

.. class:: IMAGE_OPTIONAL_HEADER32

    Alias for :class:`_IMAGE_OPTIONAL_HEADER`

.. class:: _IMAGE_OPTIONAL_HEADER

    .. attribute:: Magic

        :class:`WORD`


    .. attribute:: MajorLinkerVersion

        :class:`BYTE`


    .. attribute:: MinorLinkerVersion

        :class:`BYTE`


    .. attribute:: SizeOfCode

        :class:`DWORD`


    .. attribute:: SizeOfInitializedData

        :class:`DWORD`


    .. attribute:: SizeOfUninitializedData

        :class:`DWORD`


    .. attribute:: AddressOfEntryPoint

        :class:`DWORD`


    .. attribute:: BaseOfCode

        :class:`DWORD`


    .. attribute:: BaseOfData

        :class:`DWORD`


    .. attribute:: ImageBase

        :class:`DWORD`


    .. attribute:: SectionAlignment

        :class:`DWORD`


    .. attribute:: FileAlignment

        :class:`DWORD`


    .. attribute:: MajorOperatingSystemVersion

        :class:`WORD`


    .. attribute:: MinorOperatingSystemVersion

        :class:`WORD`


    .. attribute:: MajorImageVersion

        :class:`WORD`


    .. attribute:: MinorImageVersion

        :class:`WORD`


    .. attribute:: MajorSubsystemVersion

        :class:`WORD`


    .. attribute:: MinorSubsystemVersion

        :class:`WORD`


    .. attribute:: Win32VersionValue

        :class:`DWORD`


    .. attribute:: SizeOfImage

        :class:`DWORD`


    .. attribute:: SizeOfHeaders

        :class:`DWORD`


    .. attribute:: CheckSum

        :class:`DWORD`


    .. attribute:: Subsystem

        :class:`WORD`


    .. attribute:: DllCharacteristics

        :class:`WORD`


    .. attribute:: SizeOfStackReserve

        :class:`DWORD`


    .. attribute:: SizeOfStackCommit

        :class:`DWORD`


    .. attribute:: SizeOfHeapReserve

        :class:`DWORD`


    .. attribute:: SizeOfHeapCommit

        :class:`DWORD`


    .. attribute:: LoaderFlags

        :class:`DWORD`


    .. attribute:: NumberOfRvaAndSizes

        :class:`DWORD`


    .. attribute:: DataDirectory

        :class:`IMAGE_DATA_DIRECTORY` ``[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]``

_IMAGE_NT_HEADERS64
'''''''''''''''''''
.. class:: PIMAGE_NT_HEADERS64

    Pointer to :class:`_IMAGE_NT_HEADERS64`

.. class:: IMAGE_NT_HEADERS64

    Alias for :class:`_IMAGE_NT_HEADERS64`

.. class:: _IMAGE_NT_HEADERS64

    .. attribute:: Signature

        :class:`DWORD`


    .. attribute:: FileHeader

        :class:`IMAGE_FILE_HEADER`


    .. attribute:: OptionalHeader

        :class:`IMAGE_OPTIONAL_HEADER64`

_IMAGE_NT_HEADERS
'''''''''''''''''
.. class:: IMAGE_NT_HEADERS32

    Alias for :class:`_IMAGE_NT_HEADERS`

.. class:: PIMAGE_NT_HEADERS32

    Pointer to :class:`_IMAGE_NT_HEADERS`

.. class:: _IMAGE_NT_HEADERS

    .. attribute:: Signature

        :class:`DWORD`


    .. attribute:: FileHeader

        :class:`IMAGE_FILE_HEADER`


    .. attribute:: OptionalHeader

        :class:`IMAGE_OPTIONAL_HEADER32`

_IMAGE_IMPORT_DESCRIPTOR
''''''''''''''''''''''''
.. class:: IMAGE_IMPORT_DESCRIPTOR

    Alias for :class:`_IMAGE_IMPORT_DESCRIPTOR`

.. class:: PIMAGE_IMPORT_DESCRIPTOR

    Pointer to :class:`_IMAGE_IMPORT_DESCRIPTOR`

.. class:: _IMAGE_IMPORT_DESCRIPTOR

    .. attribute:: OriginalFirstThunk

        :class:`DWORD`


    .. attribute:: TimeDateStamp

        :class:`DWORD`


    .. attribute:: ForwarderChain

        :class:`DWORD`


    .. attribute:: Name

        :class:`DWORD`


    .. attribute:: FirstThunk

        :class:`DWORD`

_IMAGE_IMPORT_BY_NAME
'''''''''''''''''''''
.. class:: PIMAGE_IMPORT_BY_NAME

    Pointer to :class:`_IMAGE_IMPORT_BY_NAME`

.. class:: IMAGE_IMPORT_BY_NAME

    Alias for :class:`_IMAGE_IMPORT_BY_NAME`

.. class:: _IMAGE_IMPORT_BY_NAME

    .. attribute:: Hint

        :class:`WORD`


    .. attribute:: Name

        :class:`BYTE` ``[1]``

_IMAGE_EXPORT_DIRECTORY
'''''''''''''''''''''''
.. class:: IMAGE_EXPORT_DIRECTORY

    Alias for :class:`_IMAGE_EXPORT_DIRECTORY`

.. class:: PIMAGE_EXPORT_DIRECTORY

    Pointer to :class:`_IMAGE_EXPORT_DIRECTORY`

.. class:: _IMAGE_EXPORT_DIRECTORY

    .. attribute:: Characteristics

        :class:`DWORD`


    .. attribute:: TimeDateStamp

        :class:`DWORD`


    .. attribute:: MajorVersion

        :class:`WORD`


    .. attribute:: MinorVersion

        :class:`WORD`


    .. attribute:: Name

        :class:`DWORD`


    .. attribute:: Base

        :class:`DWORD`


    .. attribute:: NumberOfFunctions

        :class:`DWORD`


    .. attribute:: NumberOfNames

        :class:`DWORD`


    .. attribute:: AddressOfFunctions

        :class:`DWORD`


    .. attribute:: AddressOfNames

        :class:`DWORD`


    .. attribute:: AddressOfNameOrdinals

        :class:`DWORD`

_IMAGE_BASE_RELOCATION
''''''''''''''''''''''
.. class:: PIMAGE_BASE_RELOCATION

    Pointer to :class:`_IMAGE_BASE_RELOCATION`

.. class:: IMAGE_BASE_RELOCATION

    Alias for :class:`_IMAGE_BASE_RELOCATION`

.. class:: _IMAGE_BASE_RELOCATION

    .. attribute:: VirtualAddress

        :class:`DWORD`


    .. attribute:: SizeOfBlock

        :class:`DWORD`

_MEMORY_BASIC_INFORMATION
'''''''''''''''''''''''''
.. class:: PMEMORY_BASIC_INFORMATION

    Pointer to :class:`_MEMORY_BASIC_INFORMATION`

.. class:: MEMORY_BASIC_INFORMATION

    Alias for :class:`_MEMORY_BASIC_INFORMATION`

.. class:: _MEMORY_BASIC_INFORMATION

    .. attribute:: BaseAddress

        :class:`PVOID`


    .. attribute:: AllocationBase

        :class:`PVOID`


    .. attribute:: AllocationProtect

        :class:`DWORD`


    .. attribute:: RegionSize

        :class:`SIZE_T`


    .. attribute:: State

        :class:`DWORD`


    .. attribute:: Protect

        :class:`DWORD`


    .. attribute:: Type

        :class:`DWORD`

_THREAD_BASIC_INFORMATION
'''''''''''''''''''''''''
.. class:: THREAD_BASIC_INFORMATION

    Alias for :class:`_THREAD_BASIC_INFORMATION`

.. class:: PTHREAD_BASIC_INFORMATION

    Pointer to :class:`_THREAD_BASIC_INFORMATION`

.. class:: _THREAD_BASIC_INFORMATION

    .. attribute:: ExitStatus

        :class:`NTSTATUS`


    .. attribute:: TebBaseAddress

        :class:`PVOID`


    .. attribute:: ClientId

        :class:`CLIENT_ID`


    .. attribute:: AffinityMask

        :class:`KAFFINITY`


    .. attribute:: Priority

        :class:`KPRIORITY`


    .. attribute:: BasePriority

        :class:`KPRIORITY`

_MEMORY_BASIC_INFORMATION32
'''''''''''''''''''''''''''
.. class:: MEMORY_BASIC_INFORMATION32

    Alias for :class:`_MEMORY_BASIC_INFORMATION32`

.. class:: PMEMORY_BASIC_INFORMATION32

    Pointer to :class:`_MEMORY_BASIC_INFORMATION32`

.. class:: _MEMORY_BASIC_INFORMATION32

    .. attribute:: BaseAddress

        :class:`DWORD`


    .. attribute:: AllocationBase

        :class:`DWORD`


    .. attribute:: AllocationProtect

        :class:`DWORD`


    .. attribute:: RegionSize

        :class:`DWORD`


    .. attribute:: State

        :class:`DWORD`


    .. attribute:: Protect

        :class:`DWORD`


    .. attribute:: Type

        :class:`DWORD`

_MEMORY_BASIC_INFORMATION64
'''''''''''''''''''''''''''
.. class:: PMEMORY_BASIC_INFORMATION64

    Pointer to :class:`_MEMORY_BASIC_INFORMATION64`

.. class:: MEMORY_BASIC_INFORMATION64

    Alias for :class:`_MEMORY_BASIC_INFORMATION64`

.. class:: _MEMORY_BASIC_INFORMATION64

    .. attribute:: BaseAddress

        :class:`ULONGLONG`


    .. attribute:: AllocationBase

        :class:`ULONGLONG`


    .. attribute:: AllocationProtect

        :class:`DWORD`


    .. attribute:: __alignment1

        :class:`DWORD`


    .. attribute:: RegionSize

        :class:`ULONGLONG`


    .. attribute:: State

        :class:`DWORD`


    .. attribute:: Protect

        :class:`DWORD`


    .. attribute:: Type

        :class:`DWORD`


    .. attribute:: __alignment2

        :class:`DWORD`

_PSAPI_WORKING_SET_BLOCK
''''''''''''''''''''''''
.. class:: PSAPI_WORKING_SET_BLOCK

    Alias for :class:`_PSAPI_WORKING_SET_BLOCK`

.. class:: PPSAPI_WORKING_SET_BLOCK

    Pointer to :class:`_PSAPI_WORKING_SET_BLOCK`

.. class:: _PSAPI_WORKING_SET_BLOCK

    .. attribute:: Flags

        :class:`PVOID`

_PSAPI_WORKING_SET_BLOCK32
''''''''''''''''''''''''''
.. class:: PSAPI_WORKING_SET_BLOCK32

    Alias for :class:`_PSAPI_WORKING_SET_BLOCK32`

.. class:: PPSAPI_WORKING_SET_BLOCK32

    Pointer to :class:`_PSAPI_WORKING_SET_BLOCK32`

.. class:: _PSAPI_WORKING_SET_BLOCK32

    .. attribute:: Flags

        :class:`DWORD`

_PSAPI_WORKING_SET_BLOCK64
''''''''''''''''''''''''''
.. class:: PSAPI_WORKING_SET_BLOCK64

    Alias for :class:`_PSAPI_WORKING_SET_BLOCK64`

.. class:: PPSAPI_WORKING_SET_BLOCK64

    Pointer to :class:`_PSAPI_WORKING_SET_BLOCK64`

.. class:: _PSAPI_WORKING_SET_BLOCK64

    .. attribute:: Flags

        :class:`ULONG64`

_PSAPI_WORKING_SET_INFORMATION
''''''''''''''''''''''''''''''
.. class:: PPSAPI_WORKING_SET_INFORMATION

    Pointer to :class:`_PSAPI_WORKING_SET_INFORMATION`

.. class:: PSAPI_WORKING_SET_INFORMATION

    Alias for :class:`_PSAPI_WORKING_SET_INFORMATION`

.. class:: _PSAPI_WORKING_SET_INFORMATION

    .. attribute:: NumberOfEntries

        :class:`PVOID`


    .. attribute:: WorkingSetInfo

        :class:`PSAPI_WORKING_SET_BLOCK` ``[1]``

_PSAPI_WORKING_SET_INFORMATION32
''''''''''''''''''''''''''''''''
.. class:: PPSAPI_WORKING_SET_INFORMATION32

    Pointer to :class:`_PSAPI_WORKING_SET_INFORMATION32`

.. class:: PSAPI_WORKING_SET_INFORMATION32

    Alias for :class:`_PSAPI_WORKING_SET_INFORMATION32`

.. class:: _PSAPI_WORKING_SET_INFORMATION32

    .. attribute:: NumberOfEntries

        :class:`DWORD`


    .. attribute:: WorkingSetInfo

        :class:`PSAPI_WORKING_SET_BLOCK32` ``[1]``

_PSAPI_WORKING_SET_INFORMATION64
''''''''''''''''''''''''''''''''
.. class:: PSAPI_WORKING_SET_INFORMATION64

    Alias for :class:`_PSAPI_WORKING_SET_INFORMATION64`

.. class:: PPSAPI_WORKING_SET_INFORMATION64

    Pointer to :class:`_PSAPI_WORKING_SET_INFORMATION64`

.. class:: _PSAPI_WORKING_SET_INFORMATION64

    .. attribute:: NumberOfEntries

        :class:`ULONG64`


    .. attribute:: WorkingSetInfo

        :class:`PSAPI_WORKING_SET_BLOCK64` ``[1]``

_PSAPI_WORKING_SET_EX_BLOCK
'''''''''''''''''''''''''''
.. class:: PSAPI_WORKING_SET_EX_BLOCK

    Alias for :class:`_PSAPI_WORKING_SET_EX_BLOCK`

.. class:: PPSAPI_WORKING_SET_EX_BLOCK

    Pointer to :class:`_PSAPI_WORKING_SET_EX_BLOCK`

.. class:: _PSAPI_WORKING_SET_EX_BLOCK

    .. attribute:: Flags

        :class:`PVOID`

_PSAPI_WORKING_SET_EX_BLOCK32
'''''''''''''''''''''''''''''
.. class:: PPSAPI_WORKING_SET_EX_BLOCK32

    Pointer to :class:`_PSAPI_WORKING_SET_EX_BLOCK32`

.. class:: PSAPI_WORKING_SET_EX_BLOCK32

    Alias for :class:`_PSAPI_WORKING_SET_EX_BLOCK32`

.. class:: _PSAPI_WORKING_SET_EX_BLOCK32

    .. attribute:: Flags

        :class:`DWORD`

_PSAPI_WORKING_SET_EX_BLOCK64
'''''''''''''''''''''''''''''
.. class:: PSAPI_WORKING_SET_EX_BLOCK64

    Alias for :class:`_PSAPI_WORKING_SET_EX_BLOCK64`

.. class:: PPSAPI_WORKING_SET_EX_BLOCK64

    Pointer to :class:`_PSAPI_WORKING_SET_EX_BLOCK64`

.. class:: _PSAPI_WORKING_SET_EX_BLOCK64

    .. attribute:: Flags

        :class:`ULONG64`

_PSAPI_WORKING_SET_EX_INFORMATION
'''''''''''''''''''''''''''''''''
.. class:: PPSAPI_WORKING_SET_EX_INFORMATION

    Pointer to :class:`_PSAPI_WORKING_SET_EX_INFORMATION`

.. class:: PSAPI_WORKING_SET_EX_INFORMATION

    Alias for :class:`_PSAPI_WORKING_SET_EX_INFORMATION`

.. class:: _PSAPI_WORKING_SET_EX_INFORMATION

    .. attribute:: VirtualAddress

        :class:`PVOID`


    .. attribute:: VirtualAttributes

        :class:`PSAPI_WORKING_SET_EX_BLOCK`

_PSAPI_WORKING_SET_EX_INFORMATION32
'''''''''''''''''''''''''''''''''''
.. class:: PSAPI_WORKING_SET_EX_INFORMATION32

    Alias for :class:`_PSAPI_WORKING_SET_EX_INFORMATION32`

.. class:: PPSAPI_WORKING_SET_EX_INFORMATION32

    Pointer to :class:`_PSAPI_WORKING_SET_EX_INFORMATION32`

.. class:: _PSAPI_WORKING_SET_EX_INFORMATION32

    .. attribute:: VirtualAddress

        :class:`DWORD`


    .. attribute:: VirtualAttributes

        :class:`PSAPI_WORKING_SET_EX_BLOCK32`

_PSAPI_WORKING_SET_EX_INFORMATION64
'''''''''''''''''''''''''''''''''''
.. class:: PPSAPI_WORKING_SET_EX_INFORMATION64

    Pointer to :class:`_PSAPI_WORKING_SET_EX_INFORMATION64`

.. class:: PSAPI_WORKING_SET_EX_INFORMATION64

    Alias for :class:`_PSAPI_WORKING_SET_EX_INFORMATION64`

.. class:: _PSAPI_WORKING_SET_EX_INFORMATION64

    .. attribute:: VirtualAddress

        :class:`ULONG64`


    .. attribute:: VirtualAttributes

        :class:`PSAPI_WORKING_SET_EX_BLOCK64`

_STARTUPINFOA
'''''''''''''
.. class:: LPSTARTUPINFOA

    Pointer to :class:`_STARTUPINFOA`

.. class:: STARTUPINFOA

    Alias for :class:`_STARTUPINFOA`

.. class:: _STARTUPINFOA

    .. attribute:: cb

        :class:`DWORD`


    .. attribute:: lpReserved

        :class:`LPSTR`


    .. attribute:: lpDesktop

        :class:`LPSTR`


    .. attribute:: lpTitle

        :class:`LPSTR`


    .. attribute:: dwX

        :class:`DWORD`


    .. attribute:: dwY

        :class:`DWORD`


    .. attribute:: dwXSize

        :class:`DWORD`


    .. attribute:: dwYSize

        :class:`DWORD`


    .. attribute:: dwXCountChars

        :class:`DWORD`


    .. attribute:: dwYCountChars

        :class:`DWORD`


    .. attribute:: dwFillAttribute

        :class:`DWORD`


    .. attribute:: dwFlags

        :class:`DWORD`


    .. attribute:: wShowWindow

        :class:`WORD`


    .. attribute:: cbReserved2

        :class:`WORD`


    .. attribute:: lpReserved2

        :class:`LPBYTE`


    .. attribute:: hStdInput

        :class:`HANDLE`


    .. attribute:: hStdOutput

        :class:`HANDLE`


    .. attribute:: hStdError

        :class:`HANDLE`

_STARTUPINFOW
'''''''''''''
.. class:: STARTUPINFOW

    Alias for :class:`_STARTUPINFOW`

.. class:: LPSTARTUPINFOW

    Pointer to :class:`_STARTUPINFOW`

.. class:: _STARTUPINFOW

    .. attribute:: cb

        :class:`DWORD`


    .. attribute:: lpReserved

        :class:`LPWSTR`


    .. attribute:: lpDesktop

        :class:`LPWSTR`


    .. attribute:: lpTitle

        :class:`LPWSTR`


    .. attribute:: dwX

        :class:`DWORD`


    .. attribute:: dwY

        :class:`DWORD`


    .. attribute:: dwXSize

        :class:`DWORD`


    .. attribute:: dwYSize

        :class:`DWORD`


    .. attribute:: dwXCountChars

        :class:`DWORD`


    .. attribute:: dwYCountChars

        :class:`DWORD`


    .. attribute:: dwFillAttribute

        :class:`DWORD`


    .. attribute:: dwFlags

        :class:`DWORD`


    .. attribute:: wShowWindow

        :class:`WORD`


    .. attribute:: cbReserved2

        :class:`WORD`


    .. attribute:: lpReserved2

        :class:`LPBYTE`


    .. attribute:: hStdInput

        :class:`HANDLE`


    .. attribute:: hStdOutput

        :class:`HANDLE`


    .. attribute:: hStdError

        :class:`HANDLE`

_STARTUPINFOEXA
'''''''''''''''
.. class:: LPSTARTUPINFOEXA

    Pointer to :class:`_STARTUPINFOEXA`

.. class:: STARTUPINFOEXA

    Alias for :class:`_STARTUPINFOEXA`

.. class:: _STARTUPINFOEXA

    .. attribute:: StartupInfo

        :class:`STARTUPINFOA`


    .. attribute:: lpAttributeList

        :class:`LPPROC_THREAD_ATTRIBUTE_LIST`

_STARTUPINFOEXW
'''''''''''''''
.. class:: STARTUPINFOEXW

    Alias for :class:`_STARTUPINFOEXW`

.. class:: LPSTARTUPINFOEXW

    Pointer to :class:`_STARTUPINFOEXW`

.. class:: _STARTUPINFOEXW

    .. attribute:: StartupInfo

        :class:`STARTUPINFOW`


    .. attribute:: lpAttributeList

        :class:`LPPROC_THREAD_ATTRIBUTE_LIST`

_PROCESS_INFORMATION
''''''''''''''''''''
.. class:: LPPROCESS_INFORMATION

    Pointer to :class:`_PROCESS_INFORMATION`

.. class:: PROCESS_INFORMATION

    Alias for :class:`_PROCESS_INFORMATION`

.. class:: PPROCESS_INFORMATION

    Pointer to :class:`_PROCESS_INFORMATION`

.. class:: _PROCESS_INFORMATION

    .. attribute:: hProcess

        :class:`HANDLE`


    .. attribute:: hThread

        :class:`HANDLE`


    .. attribute:: dwProcessId

        :class:`DWORD`


    .. attribute:: dwThreadId

        :class:`DWORD`

_FLOATING_SAVE_AREA
'''''''''''''''''''
.. class:: FLOATING_SAVE_AREA

    Alias for :class:`_FLOATING_SAVE_AREA`

.. class:: _FLOATING_SAVE_AREA

    .. attribute:: ControlWord

        :class:`DWORD`


    .. attribute:: StatusWord

        :class:`DWORD`


    .. attribute:: TagWord

        :class:`DWORD`


    .. attribute:: ErrorOffset

        :class:`DWORD`


    .. attribute:: ErrorSelector

        :class:`DWORD`


    .. attribute:: DataOffset

        :class:`DWORD`


    .. attribute:: DataSelector

        :class:`DWORD`


    .. attribute:: RegisterArea

        :class:`BYTE` ``[80]``


    .. attribute:: Cr0NpxState

        :class:`DWORD`

_CONTEXT32
''''''''''
.. class:: PCONTEXT32

    Pointer to :class:`_CONTEXT32`

.. class:: CONTEXT32

    Alias for :class:`_CONTEXT32`

.. class:: LPCONTEXT32

    Pointer to :class:`_CONTEXT32`

.. class:: _CONTEXT32

    .. attribute:: ContextFlags

        :class:`DWORD`


    .. attribute:: Dr0

        :class:`DWORD`


    .. attribute:: Dr1

        :class:`DWORD`


    .. attribute:: Dr2

        :class:`DWORD`


    .. attribute:: Dr3

        :class:`DWORD`


    .. attribute:: Dr6

        :class:`DWORD`


    .. attribute:: Dr7

        :class:`DWORD`


    .. attribute:: FloatSave

        :class:`FLOATING_SAVE_AREA`


    .. attribute:: SegGs

        :class:`DWORD`


    .. attribute:: SegFs

        :class:`DWORD`


    .. attribute:: SegEs

        :class:`DWORD`


    .. attribute:: SegDs

        :class:`DWORD`


    .. attribute:: Edi

        :class:`DWORD`


    .. attribute:: Esi

        :class:`DWORD`


    .. attribute:: Ebx

        :class:`DWORD`


    .. attribute:: Edx

        :class:`DWORD`


    .. attribute:: Ecx

        :class:`DWORD`


    .. attribute:: Eax

        :class:`DWORD`


    .. attribute:: Ebp

        :class:`DWORD`


    .. attribute:: Eip

        :class:`DWORD`


    .. attribute:: SegCs

        :class:`DWORD`


    .. attribute:: EFlags

        :class:`DWORD`


    .. attribute:: Esp

        :class:`DWORD`


    .. attribute:: SegSs

        :class:`DWORD`


    .. attribute:: ExtendedRegisters

        :class:`BYTE` ``[512]``

_WOW64_FLOATING_SAVE_AREA
'''''''''''''''''''''''''
.. class:: WOW64_FLOATING_SAVE_AREA

    Alias for :class:`_WOW64_FLOATING_SAVE_AREA`

.. class:: _WOW64_FLOATING_SAVE_AREA

    .. attribute:: ControlWord

        :class:`DWORD`


    .. attribute:: StatusWord

        :class:`DWORD`


    .. attribute:: TagWord

        :class:`DWORD`


    .. attribute:: ErrorOffset

        :class:`DWORD`


    .. attribute:: ErrorSelector

        :class:`DWORD`


    .. attribute:: DataOffset

        :class:`DWORD`


    .. attribute:: DataSelector

        :class:`DWORD`


    .. attribute:: RegisterArea

        :class:`BYTE` ``[WOW64_SIZE_OF_80387_REGISTERS]``


    .. attribute:: Cr0NpxState

        :class:`DWORD`

_WOW64_CONTEXT
''''''''''''''
.. class:: PWOW64_CONTEXT

    Pointer to :class:`_WOW64_CONTEXT`

.. class:: WOW64_CONTEXT

    Alias for :class:`_WOW64_CONTEXT`

.. class:: _WOW64_CONTEXT

    .. attribute:: ContextFlags

        :class:`DWORD`


    .. attribute:: Dr0

        :class:`DWORD`


    .. attribute:: Dr1

        :class:`DWORD`


    .. attribute:: Dr2

        :class:`DWORD`


    .. attribute:: Dr3

        :class:`DWORD`


    .. attribute:: Dr6

        :class:`DWORD`


    .. attribute:: Dr7

        :class:`DWORD`


    .. attribute:: FloatSave

        :class:`WOW64_FLOATING_SAVE_AREA`


    .. attribute:: SegGs

        :class:`DWORD`


    .. attribute:: SegFs

        :class:`DWORD`


    .. attribute:: SegEs

        :class:`DWORD`


    .. attribute:: SegDs

        :class:`DWORD`


    .. attribute:: Edi

        :class:`DWORD`


    .. attribute:: Esi

        :class:`DWORD`


    .. attribute:: Ebx

        :class:`DWORD`


    .. attribute:: Edx

        :class:`DWORD`


    .. attribute:: Ecx

        :class:`DWORD`


    .. attribute:: Eax

        :class:`DWORD`


    .. attribute:: Ebp

        :class:`DWORD`


    .. attribute:: Eip

        :class:`DWORD`


    .. attribute:: SegCs

        :class:`DWORD`


    .. attribute:: EFlags

        :class:`DWORD`


    .. attribute:: Esp

        :class:`DWORD`


    .. attribute:: SegSs

        :class:`DWORD`


    .. attribute:: ExtendedRegisters

        :class:`BYTE` ``[WOW64_MAXIMUM_SUPPORTED_EXTENSION]``

_M128A
''''''
.. class:: M128A

    Alias for :class:`_M128A`

.. class:: PM128A

    Pointer to :class:`_M128A`

.. class:: _M128A

    .. attribute:: Low

        :class:`ULONGLONG`


    .. attribute:: High

        :class:`LONGLONG`

_XSAVE_FORMAT_64
''''''''''''''''
.. class:: XSAVE_FORMAT_64

    Alias for :class:`_XSAVE_FORMAT_64`

.. class:: PXSAVE_FORMAT_64

    Pointer to :class:`_XSAVE_FORMAT_64`

.. class:: _XSAVE_FORMAT_64

    .. attribute:: ControlWord

        :class:`WORD`


    .. attribute:: StatusWord

        :class:`WORD`


    .. attribute:: TagWord

        :class:`BYTE`


    .. attribute:: Reserved1

        :class:`BYTE`


    .. attribute:: ErrorOpcode

        :class:`WORD`


    .. attribute:: ErrorOffset

        :class:`DWORD`


    .. attribute:: ErrorSelector

        :class:`WORD`


    .. attribute:: Reserved2

        :class:`WORD`


    .. attribute:: DataOffset

        :class:`DWORD`


    .. attribute:: DataSelector

        :class:`WORD`


    .. attribute:: Reserved3

        :class:`WORD`


    .. attribute:: MxCsr

        :class:`DWORD`


    .. attribute:: MxCsr_Mask

        :class:`DWORD`


    .. attribute:: FloatRegisters

        :class:`M128A` ``[8]``


    .. attribute:: XmmRegisters

        :class:`M128A` ``[16]``


    .. attribute:: Reserved4

        :class:`BYTE` ``[96]``

_XSAVE_FORMAT_32
''''''''''''''''
.. class:: XSAVE_FORMAT_32

    Alias for :class:`_XSAVE_FORMAT_32`

.. class:: PXSAVE_FORMAT_32

    Pointer to :class:`_XSAVE_FORMAT_32`

.. class:: _XSAVE_FORMAT_32

    .. attribute:: ControlWord

        :class:`WORD`


    .. attribute:: StatusWord

        :class:`WORD`


    .. attribute:: TagWord

        :class:`BYTE`


    .. attribute:: Reserved1

        :class:`BYTE`


    .. attribute:: ErrorOpcode

        :class:`WORD`


    .. attribute:: ErrorOffset

        :class:`DWORD`


    .. attribute:: ErrorSelector

        :class:`WORD`


    .. attribute:: Reserved2

        :class:`WORD`


    .. attribute:: DataOffset

        :class:`DWORD`


    .. attribute:: DataSelector

        :class:`WORD`


    .. attribute:: Reserved3

        :class:`WORD`


    .. attribute:: MxCsr

        :class:`DWORD`


    .. attribute:: MxCsr_Mask

        :class:`DWORD`


    .. attribute:: FloatRegisters

        :class:`M128A` ``[8]``


    .. attribute:: XmmRegisters

        :class:`M128A` ``[8]``


    .. attribute:: Reserved4

        :class:`BYTE` ``[192]``


    .. attribute:: StackControl

        :class:`DWORD` ``[7]``


    .. attribute:: Cr0NpxState

        :class:`DWORD`

_TMP_DUMMYSTRUCTNAME
''''''''''''''''''''
.. class:: TMP_DUMMYSTRUCTNAME

    Alias for :class:`_TMP_DUMMYSTRUCTNAME`

.. class:: _TMP_DUMMYSTRUCTNAME

    .. attribute:: Header

        :class:`M128A` ``[2]``


    .. attribute:: Legacy

        :class:`M128A` ``[8]``


    .. attribute:: Xmm0

        :class:`M128A`


    .. attribute:: Xmm1

        :class:`M128A`


    .. attribute:: Xmm2

        :class:`M128A`


    .. attribute:: Xmm3

        :class:`M128A`


    .. attribute:: Xmm4

        :class:`M128A`


    .. attribute:: Xmm5

        :class:`M128A`


    .. attribute:: Xmm6

        :class:`M128A`


    .. attribute:: Xmm7

        :class:`M128A`


    .. attribute:: Xmm8

        :class:`M128A`


    .. attribute:: Xmm9

        :class:`M128A`


    .. attribute:: Xmm10

        :class:`M128A`


    .. attribute:: Xmm11

        :class:`M128A`


    .. attribute:: Xmm12

        :class:`M128A`


    .. attribute:: Xmm13

        :class:`M128A`


    .. attribute:: Xmm14

        :class:`M128A`


    .. attribute:: Xmm15

        :class:`M128A`

_TMP_CONTEXT64_SUBUNION
'''''''''''''''''''''''
.. class:: TMP_CONTEXT64_SUBUNION

    Alias for :class:`_TMP_CONTEXT64_SUBUNION`

.. class:: _TMP_CONTEXT64_SUBUNION

    .. attribute:: FltSave

        :class:`XSAVE_FORMAT_64`


    .. attribute:: DUMMYSTRUCTNAME

        :class:`TMP_DUMMYSTRUCTNAME`

_CONTEXT64
''''''''''
.. class:: PCONTEXT64

    Pointer to :class:`_CONTEXT64`

.. class:: CONTEXT64

    Alias for :class:`_CONTEXT64`

.. class:: LPCONTEXT64

    Pointer to :class:`_CONTEXT64`

.. class:: _CONTEXT64

    .. attribute:: P1Home

        :class:`DWORD64`


    .. attribute:: P2Home

        :class:`DWORD64`


    .. attribute:: P3Home

        :class:`DWORD64`


    .. attribute:: P4Home

        :class:`DWORD64`


    .. attribute:: P5Home

        :class:`DWORD64`


    .. attribute:: P6Home

        :class:`DWORD64`


    .. attribute:: ContextFlags

        :class:`DWORD`


    .. attribute:: MxCsr

        :class:`DWORD`


    .. attribute:: SegCs

        :class:`WORD`


    .. attribute:: SegDs

        :class:`WORD`


    .. attribute:: SegEs

        :class:`WORD`


    .. attribute:: SegFs

        :class:`WORD`


    .. attribute:: SegGs

        :class:`WORD`


    .. attribute:: SegSs

        :class:`WORD`


    .. attribute:: EFlags

        :class:`DWORD`


    .. attribute:: Dr0

        :class:`DWORD64`


    .. attribute:: Dr1

        :class:`DWORD64`


    .. attribute:: Dr2

        :class:`DWORD64`


    .. attribute:: Dr3

        :class:`DWORD64`


    .. attribute:: Dr6

        :class:`DWORD64`


    .. attribute:: Dr7

        :class:`DWORD64`


    .. attribute:: Rax

        :class:`DWORD64`


    .. attribute:: Rcx

        :class:`DWORD64`


    .. attribute:: Rdx

        :class:`DWORD64`


    .. attribute:: Rbx

        :class:`DWORD64`


    .. attribute:: Rsp

        :class:`DWORD64`


    .. attribute:: Rbp

        :class:`DWORD64`


    .. attribute:: Rsi

        :class:`DWORD64`


    .. attribute:: Rdi

        :class:`DWORD64`


    .. attribute:: R8

        :class:`DWORD64`


    .. attribute:: R9

        :class:`DWORD64`


    .. attribute:: R10

        :class:`DWORD64`


    .. attribute:: R11

        :class:`DWORD64`


    .. attribute:: R12

        :class:`DWORD64`


    .. attribute:: R13

        :class:`DWORD64`


    .. attribute:: R14

        :class:`DWORD64`


    .. attribute:: R15

        :class:`DWORD64`


    .. attribute:: Rip

        :class:`DWORD64`


    .. attribute:: DUMMYUNIONNAME

        :class:`TMP_CONTEXT64_SUBUNION`


    .. attribute:: VectorRegister

        :class:`M128A` ``[26]``


    .. attribute:: VectorControl

        :class:`DWORD64`


    .. attribute:: DebugControl

        :class:`DWORD64`


    .. attribute:: LastBranchToRip

        :class:`DWORD64`


    .. attribute:: LastBranchFromRip

        :class:`DWORD64`


    .. attribute:: LastExceptionToRip

        :class:`DWORD64`


    .. attribute:: LastExceptionFromRip

        :class:`DWORD64`

tagPROCESSENTRY32W
''''''''''''''''''
.. class:: PPROCESSENTRY32W

    Pointer to :class:`tagPROCESSENTRY32W`

.. class:: LPPROCESSENTRY32W

    Pointer to :class:`tagPROCESSENTRY32W`

.. class:: PROCESSENTRY32W

    Alias for :class:`tagPROCESSENTRY32W`

.. class:: tagPROCESSENTRY32W

    .. attribute:: dwSize

        :class:`DWORD`


    .. attribute:: cntUsage

        :class:`DWORD`


    .. attribute:: th32ProcessID

        :class:`DWORD`


    .. attribute:: th32DefaultHeapID

        :class:`ULONG_PTR`


    .. attribute:: th32ModuleID

        :class:`DWORD`


    .. attribute:: cntThreads

        :class:`DWORD`


    .. attribute:: th32ParentProcessID

        :class:`DWORD`


    .. attribute:: pcPriClassBase

        :class:`LONG`


    .. attribute:: dwFlags

        :class:`DWORD`


    .. attribute:: szExeFile

        :class:`WCHAR` ``[MAX_PATH]``

tagPROCESSENTRY32
'''''''''''''''''
.. class:: PROCESSENTRY32

    Alias for :class:`tagPROCESSENTRY32`

.. class:: PPROCESSENTRY32

    Pointer to :class:`tagPROCESSENTRY32`

.. class:: LPPROCESSENTRY32

    Pointer to :class:`tagPROCESSENTRY32`

.. class:: tagPROCESSENTRY32

    .. attribute:: dwSize

        :class:`DWORD`


    .. attribute:: cntUsage

        :class:`DWORD`


    .. attribute:: th32ProcessID

        :class:`DWORD`


    .. attribute:: th32DefaultHeapID

        :class:`ULONG_PTR`


    .. attribute:: th32ModuleID

        :class:`DWORD`


    .. attribute:: cntThreads

        :class:`DWORD`


    .. attribute:: th32ParentProcessID

        :class:`DWORD`


    .. attribute:: pcPriClassBase

        :class:`LONG`


    .. attribute:: dwFlags

        :class:`DWORD`


    .. attribute:: szExeFile

        :class:`CHAR` ``[MAX_PATH]``

tagTHREADENTRY32
''''''''''''''''
.. class:: PTHREADENTRY32

    Pointer to :class:`tagTHREADENTRY32`

.. class:: THREADENTRY32

    Alias for :class:`tagTHREADENTRY32`

.. class:: LPTHREADENTRY32

    Pointer to :class:`tagTHREADENTRY32`

.. class:: tagTHREADENTRY32

    .. attribute:: dwSize

        :class:`DWORD`


    .. attribute:: cntUsage

        :class:`DWORD`


    .. attribute:: th32ThreadID

        :class:`DWORD`


    .. attribute:: th32OwnerProcessID

        :class:`DWORD`


    .. attribute:: tpBasePri

        :class:`LONG`


    .. attribute:: tpDeltaPri

        :class:`LONG`


    .. attribute:: dwFlags

        :class:`DWORD`

_LUID
'''''
.. class:: LUID

    Alias for :class:`_LUID`

.. class:: PLUID

    Pointer to :class:`_LUID`

.. class:: _LUID

    .. attribute:: LowPart

        :class:`DWORD`


    .. attribute:: HighPart

        :class:`LONG`

_LUID_AND_ATTRIBUTES
''''''''''''''''''''
.. class:: LUID_AND_ATTRIBUTES

    Alias for :class:`_LUID_AND_ATTRIBUTES`

.. class:: PLUID_AND_ATTRIBUTES

    Pointer to :class:`_LUID_AND_ATTRIBUTES`

.. class:: _LUID_AND_ATTRIBUTES

    .. attribute:: Luid

        :class:`LUID`


    .. attribute:: Attributes

        :class:`DWORD`

_TOKEN_PRIVILEGES
'''''''''''''''''
.. class:: TOKEN_PRIVILEGES

    Alias for :class:`_TOKEN_PRIVILEGES`

.. class:: PTOKEN_PRIVILEGES

    Pointer to :class:`_TOKEN_PRIVILEGES`

.. class:: _TOKEN_PRIVILEGES

    .. attribute:: PrivilegeCount

        :class:`DWORD`


    .. attribute:: Privileges

        :class:`LUID_AND_ATTRIBUTES` ``[ANYSIZE_ARRAY]``

_TOKEN_ELEVATION
''''''''''''''''
.. class:: TOKEN_ELEVATION

    Alias for :class:`_TOKEN_ELEVATION`

.. class:: PTOKEN_ELEVATION

    Pointer to :class:`_TOKEN_ELEVATION`

.. class:: _TOKEN_ELEVATION

    .. attribute:: TokenIsElevated

        :class:`DWORD`

_SID_AND_ATTRIBUTES
'''''''''''''''''''
.. class:: SID_AND_ATTRIBUTES

    Alias for :class:`_SID_AND_ATTRIBUTES`

.. class:: PSID_AND_ATTRIBUTES

    Pointer to :class:`_SID_AND_ATTRIBUTES`

.. class:: _SID_AND_ATTRIBUTES

    .. attribute:: Sid

        :class:`PSID`


    .. attribute:: Attributes

        :class:`DWORD`

_TOKEN_MANDATORY_LABEL
''''''''''''''''''''''
.. class:: TOKEN_MANDATORY_LABEL

    Alias for :class:`_TOKEN_MANDATORY_LABEL`

.. class:: PTOKEN_MANDATORY_LABEL

    Pointer to :class:`_TOKEN_MANDATORY_LABEL`

.. class:: _TOKEN_MANDATORY_LABEL

    .. attribute:: Label

        :class:`SID_AND_ATTRIBUTES`

_TOKEN_USER
'''''''''''
.. class:: PTOKEN_USER

    Pointer to :class:`_TOKEN_USER`

.. class:: TOKEN_USER

    Alias for :class:`_TOKEN_USER`

.. class:: _TOKEN_USER

    .. attribute:: User

        :class:`SID_AND_ATTRIBUTES`

_OSVERSIONINFOA
'''''''''''''''
.. class:: POSVERSIONINFOA

    Pointer to :class:`_OSVERSIONINFOA`

.. class:: OSVERSIONINFOA

    Alias for :class:`_OSVERSIONINFOA`

.. class:: LPOSVERSIONINFOA

    Pointer to :class:`_OSVERSIONINFOA`

.. class:: _OSVERSIONINFOA

    .. attribute:: dwOSVersionInfoSize

        :class:`DWORD`


    .. attribute:: dwMajorVersion

        :class:`DWORD`


    .. attribute:: dwMinorVersion

        :class:`DWORD`


    .. attribute:: dwBuildNumber

        :class:`DWORD`


    .. attribute:: dwPlatformId

        :class:`DWORD`


    .. attribute:: szCSDVersion

        :class:`CHAR` ``[128]``

_OSVERSIONINFOW
'''''''''''''''
.. class:: RTL_OSVERSIONINFOW

    Alias for :class:`_OSVERSIONINFOW`

.. class:: PRTL_OSVERSIONINFOW

    Pointer to :class:`_OSVERSIONINFOW`

.. class:: LPOSVERSIONINFOW

    Pointer to :class:`_OSVERSIONINFOW`

.. class:: POSVERSIONINFOW

    Pointer to :class:`_OSVERSIONINFOW`

.. class:: OSVERSIONINFOW

    Alias for :class:`_OSVERSIONINFOW`

.. class:: _OSVERSIONINFOW

    .. attribute:: dwOSVersionInfoSize

        :class:`DWORD`


    .. attribute:: dwMajorVersion

        :class:`DWORD`


    .. attribute:: dwMinorVersion

        :class:`DWORD`


    .. attribute:: dwBuildNumber

        :class:`DWORD`


    .. attribute:: dwPlatformId

        :class:`DWORD`


    .. attribute:: szCSDVersion

        :class:`WCHAR` ``[128]``

_OSVERSIONINFOEXA
'''''''''''''''''
.. class:: OSVERSIONINFOEXA

    Alias for :class:`_OSVERSIONINFOEXA`

.. class:: POSVERSIONINFOEXA

    Pointer to :class:`_OSVERSIONINFOEXA`

.. class:: LPOSVERSIONINFOEXA

    Pointer to :class:`_OSVERSIONINFOEXA`

.. class:: _OSVERSIONINFOEXA

    .. attribute:: dwOSVersionInfoSize

        :class:`DWORD`


    .. attribute:: dwMajorVersion

        :class:`DWORD`


    .. attribute:: dwMinorVersion

        :class:`DWORD`


    .. attribute:: dwBuildNumber

        :class:`DWORD`


    .. attribute:: dwPlatformId

        :class:`DWORD`


    .. attribute:: szCSDVersion

        :class:`CHAR` ``[128]``


    .. attribute:: wServicePackMajor

        :class:`WORD`


    .. attribute:: wServicePackMinor

        :class:`WORD`


    .. attribute:: wSuiteMask

        :class:`WORD`


    .. attribute:: wProductType

        :class:`BYTE`


    .. attribute:: wReserved

        :class:`BYTE`

_OSVERSIONINFOEXW
'''''''''''''''''
.. class:: PRTL_OSVERSIONINFOEXW

    Pointer to :class:`_OSVERSIONINFOEXW`

.. class:: LPOSVERSIONINFOEXW

    Pointer to :class:`_OSVERSIONINFOEXW`

.. class:: OSVERSIONINFOEXW

    Alias for :class:`_OSVERSIONINFOEXW`

.. class:: POSVERSIONINFOEXW

    Pointer to :class:`_OSVERSIONINFOEXW`

.. class:: RTL_OSVERSIONINFOEXW

    Alias for :class:`_OSVERSIONINFOEXW`

.. class:: _OSVERSIONINFOEXW

    .. attribute:: dwOSVersionInfoSize

        :class:`DWORD`


    .. attribute:: dwMajorVersion

        :class:`DWORD`


    .. attribute:: dwMinorVersion

        :class:`DWORD`


    .. attribute:: dwBuildNumber

        :class:`DWORD`


    .. attribute:: dwPlatformId

        :class:`DWORD`


    .. attribute:: szCSDVersion

        :class:`WCHAR` ``[128]``


    .. attribute:: wServicePackMajor

        :class:`WORD`


    .. attribute:: wServicePackMinor

        :class:`WORD`


    .. attribute:: wSuiteMask

        :class:`WORD`


    .. attribute:: wProductType

        :class:`BYTE`


    .. attribute:: wReserved

        :class:`BYTE`

_OVERLAPPED
'''''''''''
.. class:: LPOVERLAPPED

    Pointer to :class:`_OVERLAPPED`

.. class:: OVERLAPPED

    Alias for :class:`_OVERLAPPED`

.. class:: _OVERLAPPED

    .. attribute:: Internal

        :class:`ULONG_PTR`


    .. attribute:: InternalHigh

        :class:`ULONG_PTR`


    .. attribute:: Pointer

        :class:`PVOID`


    .. attribute:: hEvent

        :class:`HANDLE`

_MIB_IPADDRROW_XP
'''''''''''''''''
.. class:: MIB_IPADDRROW

    Alias for :class:`_MIB_IPADDRROW_XP`

.. class:: PMIB_IPADDRROW_XP

    Pointer to :class:`_MIB_IPADDRROW_XP`

.. class:: MIB_IPADDRROW_XP

    Alias for :class:`_MIB_IPADDRROW_XP`

.. class:: _MIB_IPADDRROW_XP

    .. attribute:: dwAddr

        :class:`DWORD`


    .. attribute:: dwIndex

        :class:`IF_INDEX`


    .. attribute:: dwMask

        :class:`DWORD`


    .. attribute:: dwBCastAddr

        :class:`DWORD`


    .. attribute:: dwReasmSize

        :class:`DWORD`


    .. attribute:: unused1

        :class:`USHORT`


    .. attribute:: wType

        :class:`USHORT`

_MIB_IPADDRTABLE
''''''''''''''''
.. class:: PMIB_IPADDRTABLE

    Pointer to :class:`_MIB_IPADDRTABLE`

.. class:: MIB_IPADDRTABLE

    Alias for :class:`_MIB_IPADDRTABLE`

.. class:: _MIB_IPADDRTABLE

    .. attribute:: dwNumEntries

        :class:`DWORD`


    .. attribute:: table

        :class:`MIB_IPADDRROW` ``[ANY_SIZE]``

_MIB_IFROW
''''''''''
.. class:: PMIB_IFROW

    Pointer to :class:`_MIB_IFROW`

.. class:: MIB_IFROW

    Alias for :class:`_MIB_IFROW`

.. class:: _MIB_IFROW

    .. attribute:: wszName

        :class:`WCHAR` ``[MAX_INTERFACE_NAME_LEN]``


    .. attribute:: dwIndex

        :class:`IF_INDEX`


    .. attribute:: dwType

        :class:`IFTYPE`


    .. attribute:: dwMtu

        :class:`DWORD`


    .. attribute:: dwSpeed

        :class:`DWORD`


    .. attribute:: dwPhysAddrLen

        :class:`DWORD`


    .. attribute:: bPhysAddr

        :class:`BYTE` ``[MAXLEN_PHYSADDR]``


    .. attribute:: dwAdminStatus

        :class:`DWORD`


    .. attribute:: dwOperStatus

        :class:`INTERNAL_IF_OPER_STATUS`


    .. attribute:: dwLastChange

        :class:`DWORD`


    .. attribute:: dwInOctets

        :class:`DWORD`


    .. attribute:: dwInUcastPkts

        :class:`DWORD`


    .. attribute:: dwInNUcastPkts

        :class:`DWORD`


    .. attribute:: dwInDiscards

        :class:`DWORD`


    .. attribute:: dwInErrors

        :class:`DWORD`


    .. attribute:: dwInUnknownProtos

        :class:`DWORD`


    .. attribute:: dwOutOctets

        :class:`DWORD`


    .. attribute:: dwOutUcastPkts

        :class:`DWORD`


    .. attribute:: dwOutNUcastPkts

        :class:`DWORD`


    .. attribute:: dwOutDiscards

        :class:`DWORD`


    .. attribute:: dwOutErrors

        :class:`DWORD`


    .. attribute:: dwOutQLen

        :class:`DWORD`


    .. attribute:: dwDescrLen

        :class:`DWORD`


    .. attribute:: bDescr

        :class:`UCHAR` ``[MAXLEN_IFDESCR]``

_MIB_IFTABLE
''''''''''''
.. class:: PMIB_IFTABLE

    Pointer to :class:`_MIB_IFTABLE`

.. class:: MIB_IFTABLE

    Alias for :class:`_MIB_IFTABLE`

.. class:: _MIB_IFTABLE

    .. attribute:: dwNumEntries

        :class:`DWORD`


    .. attribute:: table

        :class:`MIB_IFROW` ``[ANY_SIZE]``

_MIB_TCPROW_OWNER_PID
'''''''''''''''''''''
.. class:: MIB_TCPROW_OWNER_PID

    Alias for :class:`_MIB_TCPROW_OWNER_PID`

.. class:: PMIB_TCPROW_OWNER_PID

    Pointer to :class:`_MIB_TCPROW_OWNER_PID`

.. class:: _MIB_TCPROW_OWNER_PID

    .. attribute:: dwState

        :class:`DWORD`


    .. attribute:: dwLocalAddr

        :class:`DWORD`


    .. attribute:: dwLocalPort

        :class:`DWORD`


    .. attribute:: dwRemoteAddr

        :class:`DWORD`


    .. attribute:: dwRemotePort

        :class:`DWORD`


    .. attribute:: dwOwningPid

        :class:`DWORD`

_MIB_TCPTABLE_OWNER_PID
'''''''''''''''''''''''
.. class:: MIB_TCPTABLE_OWNER_PID

    Alias for :class:`_MIB_TCPTABLE_OWNER_PID`

.. class:: PMIB_TCPTABLE_OWNER_PID

    Pointer to :class:`_MIB_TCPTABLE_OWNER_PID`

.. class:: _MIB_TCPTABLE_OWNER_PID

    .. attribute:: dwNumEntries

        :class:`DWORD`


    .. attribute:: table

        :class:`MIB_TCPROW_OWNER_PID` ``[ANY_SIZE]``

_MIB_UDPROW_OWNER_PID
'''''''''''''''''''''
.. class:: MIB_UDPROW_OWNER_PID

    Alias for :class:`_MIB_UDPROW_OWNER_PID`

.. class:: PMIB_UDPROW_OWNER_PID

    Pointer to :class:`_MIB_UDPROW_OWNER_PID`

.. class:: _MIB_UDPROW_OWNER_PID

    .. attribute:: dwLocalAddr

        :class:`DWORD`


    .. attribute:: dwLocalPort

        :class:`DWORD`


    .. attribute:: dwOwningPid

        :class:`DWORD`

_MIB_UDPTABLE_OWNER_PID
'''''''''''''''''''''''
.. class:: MIB_UDPTABLE_OWNER_PID

    Alias for :class:`_MIB_UDPTABLE_OWNER_PID`

.. class:: PMIB_UDPTABLE_OWNER_PID

    Pointer to :class:`_MIB_UDPTABLE_OWNER_PID`

.. class:: _MIB_UDPTABLE_OWNER_PID

    .. attribute:: dwNumEntries

        :class:`DWORD`


    .. attribute:: table

        :class:`MIB_UDPROW_OWNER_PID` ``[ANY_SIZE]``

_MIB_UDP6ROW_OWNER_PID
''''''''''''''''''''''
.. class:: MIB_UDP6ROW_OWNER_PID

    Alias for :class:`_MIB_UDP6ROW_OWNER_PID`

.. class:: PMIB_UDP6ROW_OWNER_PID

    Pointer to :class:`_MIB_UDP6ROW_OWNER_PID`

.. class:: _MIB_UDP6ROW_OWNER_PID

    .. attribute:: ucLocalAddr

        :class:`UCHAR` ``[16]``


    .. attribute:: dwLocalScopeId

        :class:`DWORD`


    .. attribute:: dwLocalPort

        :class:`DWORD`


    .. attribute:: dwOwningPid

        :class:`DWORD`

_MIB_UDP6TABLE_OWNER_PID
''''''''''''''''''''''''
.. class:: PMIB_UDP6TABLE_OWNER_PID

    Pointer to :class:`_MIB_UDP6TABLE_OWNER_PID`

.. class:: MIB_UDP6TABLE_OWNER_PID

    Alias for :class:`_MIB_UDP6TABLE_OWNER_PID`

.. class:: _MIB_UDP6TABLE_OWNER_PID

    .. attribute:: dwNumEntries

        :class:`DWORD`


    .. attribute:: table

        :class:`MIB_UDP6ROW_OWNER_PID` ``[ANY_SIZE]``

_MIB_TCP6ROW_OWNER_PID
''''''''''''''''''''''
.. class:: MIB_TCP6ROW_OWNER_PID

    Alias for :class:`_MIB_TCP6ROW_OWNER_PID`

.. class:: PMIB_TCP6ROW_OWNER_PID

    Pointer to :class:`_MIB_TCP6ROW_OWNER_PID`

.. class:: _MIB_TCP6ROW_OWNER_PID

    .. attribute:: ucLocalAddr

        :class:`UCHAR` ``[16]``


    .. attribute:: dwLocalScopeId

        :class:`DWORD`


    .. attribute:: dwLocalPort

        :class:`DWORD`


    .. attribute:: ucRemoteAddr

        :class:`UCHAR` ``[16]``


    .. attribute:: dwRemoteScopeId

        :class:`DWORD`


    .. attribute:: dwRemotePort

        :class:`DWORD`


    .. attribute:: dwState

        :class:`DWORD`


    .. attribute:: dwOwningPid

        :class:`DWORD`

_MIB_TCP6TABLE_OWNER_PID
''''''''''''''''''''''''
.. class:: MIB_TCP6TABLE_OWNER_PID

    Alias for :class:`_MIB_TCP6TABLE_OWNER_PID`

.. class:: PMIB_TCP6TABLE_OWNER_PID

    Pointer to :class:`_MIB_TCP6TABLE_OWNER_PID`

.. class:: _MIB_TCP6TABLE_OWNER_PID

    .. attribute:: dwNumEntries

        :class:`DWORD`


    .. attribute:: table

        :class:`MIB_TCP6ROW_OWNER_PID` ``[ANY_SIZE]``

_MIB_TCPROW
'''''''''''
.. class:: MIB_TCPROW

    Alias for :class:`_MIB_TCPROW`

.. class:: PMIB_TCPROW

    Pointer to :class:`_MIB_TCPROW`

.. class:: _MIB_TCPROW

    .. attribute:: dwState

        :class:`DWORD`


    .. attribute:: dwLocalAddr

        :class:`DWORD`


    .. attribute:: dwLocalPort

        :class:`DWORD`


    .. attribute:: dwRemoteAddr

        :class:`DWORD`


    .. attribute:: dwRemotePort

        :class:`DWORD`

_IP_ADAPTER_INDEX_MAP
'''''''''''''''''''''
.. class:: PIP_ADAPTER_INDEX_MAP

    Pointer to :class:`_IP_ADAPTER_INDEX_MAP`

.. class:: IP_ADAPTER_INDEX_MAP

    Alias for :class:`_IP_ADAPTER_INDEX_MAP`

.. class:: _IP_ADAPTER_INDEX_MAP

    .. attribute:: Index

        :class:`ULONG`


    .. attribute:: Name

        :class:`WCHAR` ``[MAX_ADAPTER_NAME]``

_IP_INTERFACE_INFO
''''''''''''''''''
.. class:: PIP_INTERFACE_INFO

    Pointer to :class:`_IP_INTERFACE_INFO`

.. class:: IP_INTERFACE_INFO

    Alias for :class:`_IP_INTERFACE_INFO`

.. class:: _IP_INTERFACE_INFO

    .. attribute:: NumAdapters

        :class:`LONG`


    .. attribute:: Adapter

        :class:`IP_ADAPTER_INDEX_MAP` ``[1]``

_EXCEPTION_RECORD
'''''''''''''''''
.. class:: PEXCEPTION_RECORD

    Pointer to :class:`_EXCEPTION_RECORD`

.. class:: EXCEPTION_RECORD

    Alias for :class:`_EXCEPTION_RECORD`

.. class:: _EXCEPTION_RECORD

    .. attribute:: ExceptionCode

        :class:`DWORD`


    .. attribute:: ExceptionFlags

        :class:`DWORD`


    .. attribute:: ExceptionRecord

        :class:`_EXCEPTION_RECORD`


    .. attribute:: ExceptionAddress

        :class:`PVOID`


    .. attribute:: NumberParameters

        :class:`DWORD`


    .. attribute:: ExceptionInformation

        :class:`ULONG_PTR` ``[EXCEPTION_MAXIMUM_PARAMETERS]``

_EXCEPTION_RECORD32
'''''''''''''''''''
.. class:: EXCEPTION_RECORD32

    Alias for :class:`_EXCEPTION_RECORD32`

.. class:: PEXCEPTION_RECORD32

    Pointer to :class:`_EXCEPTION_RECORD32`

.. class:: _EXCEPTION_RECORD32

    .. attribute:: ExceptionCode

        :class:`DWORD`


    .. attribute:: ExceptionFlags

        :class:`DWORD`


    .. attribute:: ExceptionRecord

        :class:`DWORD`


    .. attribute:: ExceptionAddress

        :class:`DWORD`


    .. attribute:: NumberParameters

        :class:`DWORD`


    .. attribute:: ExceptionInformation

        :class:`DWORD` ``[EXCEPTION_MAXIMUM_PARAMETERS]``

_EXCEPTION_RECORD64
'''''''''''''''''''
.. class:: PEXCEPTION_RECORD64

    Pointer to :class:`_EXCEPTION_RECORD64`

.. class:: EXCEPTION_RECORD64

    Alias for :class:`_EXCEPTION_RECORD64`

.. class:: _EXCEPTION_RECORD64

    .. attribute:: ExceptionCode

        :class:`DWORD`


    .. attribute:: ExceptionFlags

        :class:`DWORD`


    .. attribute:: ExceptionRecord

        :class:`DWORD64`


    .. attribute:: ExceptionAddress

        :class:`DWORD64`


    .. attribute:: NumberParameters

        :class:`DWORD`


    .. attribute:: __unusedAlignment

        :class:`DWORD`


    .. attribute:: ExceptionInformation

        :class:`DWORD64` ``[EXCEPTION_MAXIMUM_PARAMETERS]``

_EXCEPTION_POINTERS64
'''''''''''''''''''''
.. class:: EXCEPTION_POINTERS64

    Alias for :class:`_EXCEPTION_POINTERS64`

.. class:: PEXCEPTION_POINTERS64

    Pointer to :class:`_EXCEPTION_POINTERS64`

.. class:: _EXCEPTION_POINTERS64

    .. attribute:: ExceptionRecord

        :class:`PEXCEPTION_RECORD`


    .. attribute:: ContextRecord

        :class:`PCONTEXT64`

_EXCEPTION_POINTERS32
'''''''''''''''''''''
.. class:: PEXCEPTION_POINTERS32

    Pointer to :class:`_EXCEPTION_POINTERS32`

.. class:: EXCEPTION_POINTERS32

    Alias for :class:`_EXCEPTION_POINTERS32`

.. class:: _EXCEPTION_POINTERS32

    .. attribute:: ExceptionRecord

        :class:`PEXCEPTION_RECORD`


    .. attribute:: ContextRecord

        :class:`PCONTEXT32`

_DEBUG_PROCESSOR_IDENTIFICATION_ALPHA
'''''''''''''''''''''''''''''''''''''
.. class:: DEBUG_PROCESSOR_IDENTIFICATION_ALPHA

    Alias for :class:`_DEBUG_PROCESSOR_IDENTIFICATION_ALPHA`

.. class:: PDEBUG_PROCESSOR_IDENTIFICATION_ALPHA

    Pointer to :class:`_DEBUG_PROCESSOR_IDENTIFICATION_ALPHA`

.. class:: _DEBUG_PROCESSOR_IDENTIFICATION_ALPHA

    .. attribute:: Type

        :class:`ULONG`


    .. attribute:: Revision

        :class:`ULONG`

_DEBUG_PROCESSOR_IDENTIFICATION_AMD64
'''''''''''''''''''''''''''''''''''''
.. class:: DEBUG_PROCESSOR_IDENTIFICATION_AMD64

    Alias for :class:`_DEBUG_PROCESSOR_IDENTIFICATION_AMD64`

.. class:: PDEBUG_PROCESSOR_IDENTIFICATION_AMD64

    Pointer to :class:`_DEBUG_PROCESSOR_IDENTIFICATION_AMD64`

.. class:: _DEBUG_PROCESSOR_IDENTIFICATION_AMD64

    .. attribute:: Family

        :class:`ULONG`


    .. attribute:: Model

        :class:`ULONG`


    .. attribute:: Stepping

        :class:`ULONG`


    .. attribute:: VendorString

        :class:`CHAR` ``[16]``

_DEBUG_PROCESSOR_IDENTIFICATION_IA64
''''''''''''''''''''''''''''''''''''
.. class:: PDEBUG_PROCESSOR_IDENTIFICATION_IA64

    Pointer to :class:`_DEBUG_PROCESSOR_IDENTIFICATION_IA64`

.. class:: DEBUG_PROCESSOR_IDENTIFICATION_IA64

    Alias for :class:`_DEBUG_PROCESSOR_IDENTIFICATION_IA64`

.. class:: _DEBUG_PROCESSOR_IDENTIFICATION_IA64

    .. attribute:: Model

        :class:`ULONG`


    .. attribute:: Revision

        :class:`ULONG`


    .. attribute:: Family

        :class:`ULONG`


    .. attribute:: ArchRev

        :class:`ULONG`


    .. attribute:: VendorString

        :class:`CHAR` ``[16]``

_DEBUG_PROCESSOR_IDENTIFICATION_X86
'''''''''''''''''''''''''''''''''''
.. class:: DEBUG_PROCESSOR_IDENTIFICATION_X86

    Alias for :class:`_DEBUG_PROCESSOR_IDENTIFICATION_X86`

.. class:: PDEBUG_PROCESSOR_IDENTIFICATION_X86

    Pointer to :class:`_DEBUG_PROCESSOR_IDENTIFICATION_X86`

.. class:: _DEBUG_PROCESSOR_IDENTIFICATION_X86

    .. attribute:: Family

        :class:`ULONG`


    .. attribute:: Model

        :class:`ULONG`


    .. attribute:: Stepping

        :class:`ULONG`


    .. attribute:: VendorString

        :class:`CHAR` ``[16]``

_DEBUG_PROCESSOR_IDENTIFICATION_ARM
'''''''''''''''''''''''''''''''''''
.. class:: DEBUG_PROCESSOR_IDENTIFICATION_ARM

    Alias for :class:`_DEBUG_PROCESSOR_IDENTIFICATION_ARM`

.. class:: PDEBUG_PROCESSOR_IDENTIFICATION_ARM

    Pointer to :class:`_DEBUG_PROCESSOR_IDENTIFICATION_ARM`

.. class:: _DEBUG_PROCESSOR_IDENTIFICATION_ARM

    .. attribute:: Type

        :class:`ULONG`


    .. attribute:: Revision

        :class:`ULONG`

_DEBUG_PROCESSOR_IDENTIFICATION_ALL
'''''''''''''''''''''''''''''''''''
.. class:: PDEBUG_PROCESSOR_IDENTIFICATION_ALL

    Pointer to :class:`_DEBUG_PROCESSOR_IDENTIFICATION_ALL`

.. class:: DEBUG_PROCESSOR_IDENTIFICATION_ALL

    Alias for :class:`_DEBUG_PROCESSOR_IDENTIFICATION_ALL`

.. class:: _DEBUG_PROCESSOR_IDENTIFICATION_ALL

    .. attribute:: Alpha

        :class:`DEBUG_PROCESSOR_IDENTIFICATION_ALPHA`


    .. attribute:: Amd64

        :class:`DEBUG_PROCESSOR_IDENTIFICATION_AMD64`


    .. attribute:: Ia64

        :class:`DEBUG_PROCESSOR_IDENTIFICATION_IA64`


    .. attribute:: X86

        :class:`DEBUG_PROCESSOR_IDENTIFICATION_X86`


    .. attribute:: Arm

        :class:`DEBUG_PROCESSOR_IDENTIFICATION_ARM`

_SYMBOL_INFO
''''''''''''
.. class:: SYMBOL_INFO

    Alias for :class:`_SYMBOL_INFO`

.. class:: PSYMBOL_INFO

    Pointer to :class:`_SYMBOL_INFO`

.. class:: _SYMBOL_INFO

    .. attribute:: SizeOfStruct

        :class:`ULONG`


    .. attribute:: TypeIndex

        :class:`ULONG`


    .. attribute:: Reserved

        :class:`ULONG64` ``[2]``


    .. attribute:: Index

        :class:`ULONG`


    .. attribute:: Size

        :class:`ULONG`


    .. attribute:: ModBase

        :class:`ULONG64`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: Value

        :class:`ULONG64`


    .. attribute:: Address

        :class:`ULONG64`


    .. attribute:: Register

        :class:`ULONG`


    .. attribute:: Scope

        :class:`ULONG`


    .. attribute:: Tag

        :class:`ULONG`


    .. attribute:: NameLen

        :class:`ULONG`


    .. attribute:: MaxNameLen

        :class:`ULONG`


    .. attribute:: Name

        :class:`CHAR` ``[1]``

_MODLOAD_DATA
'''''''''''''
.. class:: PMODLOAD_DATA

    Pointer to :class:`_MODLOAD_DATA`

.. class:: MODLOAD_DATA

    Alias for :class:`_MODLOAD_DATA`

.. class:: _MODLOAD_DATA

    .. attribute:: ssize

        :class:`DWORD`


    .. attribute:: ssig

        :class:`DWORD`


    .. attribute:: data

        :class:`PVOID`


    .. attribute:: size

        :class:`DWORD`


    .. attribute:: flags

        :class:`DWORD`

_SYSTEM_MODULE32
''''''''''''''''
.. class:: SYSTEM_MODULE32

    Alias for :class:`_SYSTEM_MODULE32`

.. class:: PSYSTEM_MODULE32

    Pointer to :class:`_SYSTEM_MODULE32`

.. class:: _SYSTEM_MODULE32

    .. attribute:: Reserved

        :class:`ULONG` ``[2]``


    .. attribute:: Base

        :class:`ULONG`


    .. attribute:: Size

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: Index

        :class:`USHORT`


    .. attribute:: Unknown

        :class:`USHORT`


    .. attribute:: LoadCount

        :class:`USHORT`


    .. attribute:: ModuleNameOffset

        :class:`USHORT`


    .. attribute:: ImageName

        :class:`CHAR` ``[256]``

_SYSTEM_MODULE64
''''''''''''''''
.. class:: SYSTEM_MODULE64

    Alias for :class:`_SYSTEM_MODULE64`

.. class:: PSYSTEM_MODULE64

    Pointer to :class:`_SYSTEM_MODULE64`

.. class:: _SYSTEM_MODULE64

    .. attribute:: Reserved

        :class:`ULONG` ``[4]``


    .. attribute:: Base

        :class:`ULONG64`


    .. attribute:: Size

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: Index

        :class:`USHORT`


    .. attribute:: Unknown

        :class:`USHORT`


    .. attribute:: LoadCount

        :class:`USHORT`


    .. attribute:: ModuleNameOffset

        :class:`USHORT`


    .. attribute:: ImageName

        :class:`CHAR` ``[256]``

_SYSTEM_MODULE_INFORMATION32
''''''''''''''''''''''''''''
.. class:: PSYSTEM_MODULE_INFORMATION32

    Pointer to :class:`_SYSTEM_MODULE_INFORMATION32`

.. class:: SYSTEM_MODULE_INFORMATION32

    Alias for :class:`_SYSTEM_MODULE_INFORMATION32`

.. class:: _SYSTEM_MODULE_INFORMATION32

    .. attribute:: ModulesCount

        :class:`ULONG`


    .. attribute:: Modules

        :class:`SYSTEM_MODULE32` ``[0]``

_SYSTEM_MODULE_INFORMATION64
''''''''''''''''''''''''''''
.. class:: PSYSTEM_MODULE_INFORMATION64

    Pointer to :class:`_SYSTEM_MODULE_INFORMATION64`

.. class:: SYSTEM_MODULE_INFORMATION64

    Alias for :class:`_SYSTEM_MODULE_INFORMATION64`

.. class:: _SYSTEM_MODULE_INFORMATION64

    .. attribute:: ModulesCount

        :class:`ULONG`


    .. attribute:: Modules

        :class:`SYSTEM_MODULE64` ``[0]``

tagSAFEARRAYBOUND
'''''''''''''''''
.. class:: SAFEARRAYBOUND

    Alias for :class:`tagSAFEARRAYBOUND`

.. class:: LPSAFEARRAYBOUND

    Pointer to :class:`tagSAFEARRAYBOUND`

.. class:: tagSAFEARRAYBOUND

    .. attribute:: cElements

        :class:`ULONG`


    .. attribute:: lLbound

        :class:`LONG`

tagSAFEARRAY
''''''''''''
.. class:: SAFEARRAY

    Alias for :class:`tagSAFEARRAY`

.. class:: tagSAFEARRAY

    .. attribute:: cDims

        :class:`USHORT`


    .. attribute:: fFeatures

        :class:`USHORT`


    .. attribute:: cbElements

        :class:`ULONG`


    .. attribute:: cLocks

        :class:`ULONG`


    .. attribute:: pvData

        :class:`PVOID`


    .. attribute:: rgsabound

        :class:`SAFEARRAYBOUND` ``[1]``

_DEBUG_BREAKPOINT_PARAMETERS
''''''''''''''''''''''''''''
.. class:: PDEBUG_BREAKPOINT_PARAMETERS

    Pointer to :class:`_DEBUG_BREAKPOINT_PARAMETERS`

.. class:: DEBUG_BREAKPOINT_PARAMETERS

    Alias for :class:`_DEBUG_BREAKPOINT_PARAMETERS`

.. class:: _DEBUG_BREAKPOINT_PARAMETERS

    .. attribute:: Offset

        :class:`ULONG64`


    .. attribute:: Id

        :class:`ULONG`


    .. attribute:: BreakType

        :class:`ULONG`


    .. attribute:: ProcType

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: DataSize

        :class:`ULONG`


    .. attribute:: DataAccessType

        :class:`ULONG`


    .. attribute:: PassCount

        :class:`ULONG`


    .. attribute:: CurrentPassCount

        :class:`ULONG`


    .. attribute:: MatchThread

        :class:`ULONG`


    .. attribute:: CommandSize

        :class:`ULONG`


    .. attribute:: OffsetExpressionSize

        :class:`ULONG`

_DEBUG_REGISTER_DESCRIPTION
'''''''''''''''''''''''''''
.. class:: DEBUG_REGISTER_DESCRIPTION

    Alias for :class:`_DEBUG_REGISTER_DESCRIPTION`

.. class:: PDEBUG_REGISTER_DESCRIPTION

    Pointer to :class:`_DEBUG_REGISTER_DESCRIPTION`

.. class:: _DEBUG_REGISTER_DESCRIPTION

    .. attribute:: Type

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: SubregMaster

        :class:`ULONG`


    .. attribute:: SubregLength

        :class:`ULONG`


    .. attribute:: SubregMask

        :class:`ULONG64`


    .. attribute:: SubregShift

        :class:`ULONG`


    .. attribute:: Reserved0

        :class:`ULONG`

_DEBUG_STACK_FRAME
''''''''''''''''''
.. class:: PDEBUG_STACK_FRAME

    Pointer to :class:`_DEBUG_STACK_FRAME`

.. class:: DEBUG_STACK_FRAME

    Alias for :class:`_DEBUG_STACK_FRAME`

.. class:: _DEBUG_STACK_FRAME

    .. attribute:: InstructionOffset

        :class:`ULONG64`


    .. attribute:: ReturnOffset

        :class:`ULONG64`


    .. attribute:: FrameOffset

        :class:`ULONG64`


    .. attribute:: StackOffset

        :class:`ULONG64`


    .. attribute:: FuncTableEntry

        :class:`ULONG64`


    .. attribute:: Params

        :class:`ULONG64` ``[4]``


    .. attribute:: Reserved

        :class:`ULONG64` ``[6]``


    .. attribute:: Virtual

        :class:`BOOL`


    .. attribute:: FrameNumber

        :class:`ULONG`

_DEBUG_LAST_EVENT_INFO_BREAKPOINT
'''''''''''''''''''''''''''''''''
.. class:: DEBUG_LAST_EVENT_INFO_BREAKPOINT

    Alias for :class:`_DEBUG_LAST_EVENT_INFO_BREAKPOINT`

.. class:: PDEBUG_LAST_EVENT_INFO_BREAKPOINT

    Pointer to :class:`_DEBUG_LAST_EVENT_INFO_BREAKPOINT`

.. class:: _DEBUG_LAST_EVENT_INFO_BREAKPOINT

    .. attribute:: Id

        :class:`ULONG`

_DEBUG_LAST_EVENT_INFO_EXCEPTION
''''''''''''''''''''''''''''''''
.. class:: DEBUG_LAST_EVENT_INFO_EXCEPTION

    Alias for :class:`_DEBUG_LAST_EVENT_INFO_EXCEPTION`

.. class:: PDEBUG_LAST_EVENT_INFO_EXCEPTION

    Pointer to :class:`_DEBUG_LAST_EVENT_INFO_EXCEPTION`

.. class:: _DEBUG_LAST_EVENT_INFO_EXCEPTION

    .. attribute:: ExceptionRecord

        :class:`EXCEPTION_RECORD64`


    .. attribute:: FirstChance

        :class:`ULONG`

_DEBUG_LAST_EVENT_INFO_EXIT_THREAD
''''''''''''''''''''''''''''''''''
.. class:: PDEBUG_LAST_EVENT_INFO_EXIT_THREAD

    Pointer to :class:`_DEBUG_LAST_EVENT_INFO_EXIT_THREAD`

.. class:: DEBUG_LAST_EVENT_INFO_EXIT_THREAD

    Alias for :class:`_DEBUG_LAST_EVENT_INFO_EXIT_THREAD`

.. class:: _DEBUG_LAST_EVENT_INFO_EXIT_THREAD

    .. attribute:: ExitCode

        :class:`ULONG`

_DEBUG_LAST_EVENT_INFO_EXIT_PROCESS
'''''''''''''''''''''''''''''''''''
.. class:: PDEBUG_LAST_EVENT_INFO_EXIT_PROCESS

    Pointer to :class:`_DEBUG_LAST_EVENT_INFO_EXIT_PROCESS`

.. class:: DEBUG_LAST_EVENT_INFO_EXIT_PROCESS

    Alias for :class:`_DEBUG_LAST_EVENT_INFO_EXIT_PROCESS`

.. class:: _DEBUG_LAST_EVENT_INFO_EXIT_PROCESS

    .. attribute:: ExitCode

        :class:`ULONG`

_DEBUG_LAST_EVENT_INFO_LOAD_MODULE
''''''''''''''''''''''''''''''''''
.. class:: PDEBUG_LAST_EVENT_INFO_LOAD_MODULE

    Pointer to :class:`_DEBUG_LAST_EVENT_INFO_LOAD_MODULE`

.. class:: DEBUG_LAST_EVENT_INFO_LOAD_MODULE

    Alias for :class:`_DEBUG_LAST_EVENT_INFO_LOAD_MODULE`

.. class:: _DEBUG_LAST_EVENT_INFO_LOAD_MODULE

    .. attribute:: Base

        :class:`ULONG64`

_DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE
''''''''''''''''''''''''''''''''''''
.. class:: PDEBUG_LAST_EVENT_INFO_UNLOAD_MODULE

    Pointer to :class:`_DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE`

.. class:: DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE

    Alias for :class:`_DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE`

.. class:: _DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE

    .. attribute:: Base

        :class:`ULONG64`

_DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR
'''''''''''''''''''''''''''''''''''
.. class:: PDEBUG_LAST_EVENT_INFO_SYSTEM_ERROR

    Pointer to :class:`_DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR`

.. class:: DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR

    Alias for :class:`_DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR`

.. class:: _DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR

    .. attribute:: Error

        :class:`ULONG`


    .. attribute:: Level

        :class:`ULONG`

_DEBUG_SPECIFIC_FILTER_PARAMETERS
'''''''''''''''''''''''''''''''''
.. class:: DEBUG_SPECIFIC_FILTER_PARAMETERS

    Alias for :class:`_DEBUG_SPECIFIC_FILTER_PARAMETERS`

.. class:: PDEBUG_SPECIFIC_FILTER_PARAMETERS

    Pointer to :class:`_DEBUG_SPECIFIC_FILTER_PARAMETERS`

.. class:: _DEBUG_SPECIFIC_FILTER_PARAMETERS

    .. attribute:: ExecutionOption

        :class:`ULONG`


    .. attribute:: ContinueOption

        :class:`ULONG`


    .. attribute:: TextSize

        :class:`ULONG`


    .. attribute:: CommandSize

        :class:`ULONG`


    .. attribute:: ArgumentSize

        :class:`ULONG`

_DEBUG_EXCEPTION_FILTER_PARAMETERS
''''''''''''''''''''''''''''''''''
.. class:: PDEBUG_EXCEPTION_FILTER_PARAMETERS

    Pointer to :class:`_DEBUG_EXCEPTION_FILTER_PARAMETERS`

.. class:: DEBUG_EXCEPTION_FILTER_PARAMETERS

    Alias for :class:`_DEBUG_EXCEPTION_FILTER_PARAMETERS`

.. class:: _DEBUG_EXCEPTION_FILTER_PARAMETERS

    .. attribute:: ExecutionOption

        :class:`ULONG`


    .. attribute:: ContinueOption

        :class:`ULONG`


    .. attribute:: TextSize

        :class:`ULONG`


    .. attribute:: CommandSize

        :class:`ULONG`


    .. attribute:: SecondCommandSize

        :class:`ULONG`


    .. attribute:: ExceptionCode

        :class:`ULONG`

_TMP_signscale
''''''''''''''
.. class:: _TMP_signscale

    .. attribute:: scale

        :class:`BYTE`


    .. attribute:: sign

        :class:`BYTE`

_TMP_lowmid
'''''''''''
.. class:: _TMP_lowmid

    .. attribute:: Lo32

        :class:`ULONG`


    .. attribute:: Mid32

        :class:`ULONG`

TMP_signscale_union
'''''''''''''''''''
.. class:: TMP_signscale_union

    .. attribute:: s

        :class:`_TMP_signscale`


    .. attribute:: signscale

        :class:`USHORT`

TMP_lowmid_union
''''''''''''''''
.. class:: TMP_lowmid_union

    .. attribute:: s

        :class:`_TMP_lowmid`


    .. attribute:: Lo64

        :class:`ULONGLONG`

tagDEC
''''''
.. class:: DECIMAL

    Alias for :class:`tagDEC`

.. class:: tagDEC

    .. attribute:: wReserved

        :class:`USHORT`


    .. attribute:: u1

        :class:`TMP_signscale_union`


    .. attribute:: Hi32

        :class:`ULONG`


    .. attribute:: u2

        :class:`TMP_signscale_union`

__tagBRECORD
''''''''''''
.. class:: _tagBRECORD

    Alias for :class:`__tagBRECORD`

.. class:: __tagBRECORD

    .. attribute:: pvRecord

        :class:`PVOID`


    .. attribute:: pRecInfo

        :class:`PVOID`

TMP_variant_sub_union
'''''''''''''''''''''
.. class:: TMP_variant_sub_union

    .. attribute:: llVal

        :class:`LONGLONG`


    .. attribute:: lVal

        :class:`LONG`


    .. attribute:: bVal

        :class:`BYTE`


    .. attribute:: iVal

        :class:`SHORT`


    .. attribute:: fltVal

        :class:`FLOAT`


    .. attribute:: dblVal

        :class:`DOUBLE`


    .. attribute:: boolVal

        :class:`VARIANT_BOOL`


    .. attribute:: scode

        :class:`SCODE`


    .. attribute:: bstrVal

        :class:`BSTR`


    .. attribute:: punkVal

        :class:`PVOID`


    .. attribute:: pdispVal

        :class:`PVOID`


    .. attribute:: parray

        :class:`SAFEARRAY`


    .. attribute:: pbVal

        :class:`BYTE`


    .. attribute:: piVal

        :class:`SHORT`


    .. attribute:: plVal

        :class:`LONG`


    .. attribute:: pllVal

        :class:`LONGLONG`


    .. attribute:: pfltVal

        :class:`FLOAT`


    .. attribute:: pdblVal

        :class:`DOUBLE`


    .. attribute:: pboolVal

        :class:`VARIANT_BOOL`


    .. attribute:: pscode

        :class:`SCODE`


    .. attribute:: pbstrVal

        :class:`BSTR`


    .. attribute:: byref

        :class:`PVOID`


    .. attribute:: cVal

        :class:`CHAR`


    .. attribute:: uiVal

        :class:`USHORT`


    .. attribute:: ulVal

        :class:`ULONG`


    .. attribute:: ullVal

        :class:`ULONGLONG`


    .. attribute:: intVal

        :class:`INT`


    .. attribute:: uintVal

        :class:`UINT`


    .. attribute:: pcVal

        :class:`CHAR`


    .. attribute:: puiVal

        :class:`USHORT`


    .. attribute:: pulVal

        :class:`ULONG`


    .. attribute:: pullVal

        :class:`ULONGLONG`


    .. attribute:: pintVal

        :class:`INT`


    .. attribute:: puintVal

        :class:`UINT`


    .. attribute:: _VARIANT_NAME_4

        :class:`_tagBRECORD`

__tagVARIANT
''''''''''''
.. class:: LPVARIANTARG

    Pointer to :class:`__tagVARIANT`

.. class:: VARIANTARG

    Alias for :class:`__tagVARIANT`

.. class:: VARIANT

    Alias for :class:`__tagVARIANT`

.. class:: LPVARIANT

    Pointer to :class:`__tagVARIANT`

.. class:: _tagVARIANT

    Alias for :class:`__tagVARIANT`

.. class:: __tagVARIANT

    .. attribute:: vt

        :class:`VARTYPE`


    .. attribute:: wReserved1

        :class:`WORD`


    .. attribute:: wReserved2

        :class:`WORD`


    .. attribute:: wReserved3

        :class:`WORD`


    .. attribute:: _VARIANT_NAME_3

        :class:`TMP_variant_sub_union`

tagDISPPARAMS
'''''''''''''
.. class:: DISPPARAMS

    Alias for :class:`tagDISPPARAMS`

.. class:: tagDISPPARAMS

    .. attribute:: rgvarg

        :class:`VARIANTARG`


    .. attribute:: rgdispidNamedArgs

        :class:`DISPID`


    .. attribute:: cArgs

        :class:`UINT`


    .. attribute:: cNamedArgs

        :class:`UINT`

tagEXCEPINFO
''''''''''''
.. class:: EXCEPINFO

    Alias for :class:`tagEXCEPINFO`

.. class:: tagEXCEPINFO

    .. attribute:: wCode

        :class:`WORD`


    .. attribute:: wReserved

        :class:`WORD`


    .. attribute:: bstrSource

        :class:`BSTR`


    .. attribute:: bstrDescription

        :class:`BSTR`


    .. attribute:: bstrHelpFile

        :class:`BSTR`


    .. attribute:: dwHelpContext

        :class:`DWORD`


    .. attribute:: pvReserved

        :class:`ULONG_PTR`


    .. attribute:: pfnDeferredFillIn

        :class:`ULONG_PTR`


    .. attribute:: scode

        :class:`SCODE`

_CERT_STRONG_SIGN_SERIALIZED_INFO
'''''''''''''''''''''''''''''''''
.. class:: CERT_STRONG_SIGN_SERIALIZED_INFO

    Alias for :class:`_CERT_STRONG_SIGN_SERIALIZED_INFO`

.. class:: PCERT_STRONG_SIGN_SERIALIZED_INFO

    Pointer to :class:`_CERT_STRONG_SIGN_SERIALIZED_INFO`

.. class:: _CERT_STRONG_SIGN_SERIALIZED_INFO

    .. attribute:: dwFlags

        :class:`DWORD`


    .. attribute:: pwszCNGSignHashAlgids

        :class:`LPWSTR`


    .. attribute:: pwszCNGPubKeyMinBitLengths

        :class:`LPWSTR`

TMP_CERT_STRONG_SIGN_PARA_UNION_TYPE
''''''''''''''''''''''''''''''''''''
.. class:: TMP_CERT_STRONG_SIGN_PARA_UNION_TYPE

    .. attribute:: pvInfo

        :class:`PVOID`


    .. attribute:: pSerializedInfo

        :class:`PCERT_STRONG_SIGN_SERIALIZED_INFO`


    .. attribute:: pszOID

        :class:`LPSTR`

_CERT_STRONG_SIGN_PARA
''''''''''''''''''''''
.. class:: CERT_STRONG_SIGN_PARA

    Alias for :class:`_CERT_STRONG_SIGN_PARA`

.. class:: PCCERT_STRONG_SIGN_PARA

    Pointer to :class:`_CERT_STRONG_SIGN_PARA`

.. class:: PCERT_STRONG_SIGN_PARA

    Pointer to :class:`_CERT_STRONG_SIGN_PARA`

.. class:: _CERT_STRONG_SIGN_PARA

    .. attribute:: cbSize

        :class:`DWORD`


    .. attribute:: dwInfoChoice

        :class:`DWORD`


    .. attribute:: tmp_union

        :class:`TMP_CERT_STRONG_SIGN_PARA_UNION_TYPE`

_CRYPTOAPI_BLOB
'''''''''''''''
.. class:: CRYPT_INTEGER_BLOB

    Alias for :class:`_CRYPTOAPI_BLOB`

.. class:: PCRYPT_DATA_BLOB

    Pointer to :class:`_CRYPTOAPI_BLOB`

.. class:: PCRYPT_OBJID_BLOB

    Pointer to :class:`_CRYPTOAPI_BLOB`

.. class:: PCRYPT_DER_BLOB

    Pointer to :class:`_CRYPTOAPI_BLOB`

.. class:: PCRL_BLOB

    Pointer to :class:`_CRYPTOAPI_BLOB`

.. class:: PCRYPT_UINT_BLOB

    Pointer to :class:`_CRYPTOAPI_BLOB`

.. class:: CERT_NAME_BLOB

    Alias for :class:`_CRYPTOAPI_BLOB`

.. class:: PCRYPT_DIGEST_BLOB

    Pointer to :class:`_CRYPTOAPI_BLOB`

.. class:: PCRYPT_INTEGER_BLOB

    Pointer to :class:`_CRYPTOAPI_BLOB`

.. class:: CERT_RDN_VALUE_BLOB

    Alias for :class:`_CRYPTOAPI_BLOB`

.. class:: PCERT_NAME_BLOB

    Pointer to :class:`_CRYPTOAPI_BLOB`

.. class:: PCRYPT_HASH_BLOB

    Pointer to :class:`_CRYPTOAPI_BLOB`

.. class:: CRYPT_DATA_BLOB

    Alias for :class:`_CRYPTOAPI_BLOB`

.. class:: DATA_BLOB

    Alias for :class:`_CRYPTOAPI_BLOB`

.. class:: CRYPT_UINT_BLOB

    Alias for :class:`_CRYPTOAPI_BLOB`

.. class:: PCERT_RDN_VALUE_BLOB

    Pointer to :class:`_CRYPTOAPI_BLOB`

.. class:: CRYPT_HASH_BLOB

    Alias for :class:`_CRYPTOAPI_BLOB`

.. class:: CRL_BLOB

    Alias for :class:`_CRYPTOAPI_BLOB`

.. class:: PCERT_BLOB

    Pointer to :class:`_CRYPTOAPI_BLOB`

.. class:: CRYPT_DIGEST_BLOB

    Alias for :class:`_CRYPTOAPI_BLOB`

.. class:: CRYPT_OBJID_BLOB

    Alias for :class:`_CRYPTOAPI_BLOB`

.. class:: CERT_BLOB

    Alias for :class:`_CRYPTOAPI_BLOB`

.. class:: CRYPT_DER_BLOB

    Alias for :class:`_CRYPTOAPI_BLOB`

.. class:: PDATA_BLOB

    Pointer to :class:`_CRYPTOAPI_BLOB`

.. class:: PCRYPT_ATTR_BLOB

    Pointer to :class:`_CRYPTOAPI_BLOB`

.. class:: CRYPT_ATTR_BLOB

    Alias for :class:`_CRYPTOAPI_BLOB`

.. class:: _CRYPTOAPI_BLOB

    .. attribute:: cbData

        :class:`DWORD`


    .. attribute:: pbData

        :class:`BYTE`

CRYPTCATATTRIBUTE_
''''''''''''''''''
.. class:: CRYPTCATATTRIBUTE

    Alias for :class:`CRYPTCATATTRIBUTE_`

.. class:: PCRYPTCATATTRIBUTE

    Pointer to :class:`CRYPTCATATTRIBUTE_`

.. class:: CRYPTCATATTRIBUTE_

    .. attribute:: cbStruct

        :class:`DWORD`


    .. attribute:: pwszReferenceTag

        :class:`LPWSTR`


    .. attribute:: dwAttrTypeAndAction

        :class:`DWORD`


    .. attribute:: cbValue

        :class:`DWORD`


    .. attribute:: pbValue

        :class:`BYTE`


    .. attribute:: dwReserved

        :class:`DWORD`

_CRYPT_ATTRIBUTE_TYPE_VALUE
'''''''''''''''''''''''''''
.. class:: CRYPT_ATTRIBUTE_TYPE_VALUE

    Alias for :class:`_CRYPT_ATTRIBUTE_TYPE_VALUE`

.. class:: PCRYPT_ATTRIBUTE_TYPE_VALUE

    Pointer to :class:`_CRYPT_ATTRIBUTE_TYPE_VALUE`

.. class:: _CRYPT_ATTRIBUTE_TYPE_VALUE

    .. attribute:: pszObjId

        :class:`LPSTR`


    .. attribute:: Value

        :class:`CRYPT_OBJID_BLOB`

_CRYPT_ALGORITHM_IDENTIFIER
'''''''''''''''''''''''''''
.. class:: CRYPT_ALGORITHM_IDENTIFIER

    Alias for :class:`_CRYPT_ALGORITHM_IDENTIFIER`

.. class:: PCRYPT_ALGORITHM_IDENTIFIER

    Pointer to :class:`_CRYPT_ALGORITHM_IDENTIFIER`

.. class:: _CRYPT_ALGORITHM_IDENTIFIER

    .. attribute:: pszObjId

        :class:`LPSTR`


    .. attribute:: Parameters

        :class:`CRYPT_OBJID_BLOB`

SIP_INDIRECT_DATA_
''''''''''''''''''
.. class:: SIP_INDIRECT_DATA

    Alias for :class:`SIP_INDIRECT_DATA_`

.. class:: PSIP_INDIRECT_DATA

    Pointer to :class:`SIP_INDIRECT_DATA_`

.. class:: SIP_INDIRECT_DATA_

    .. attribute:: Data

        :class:`CRYPT_ATTRIBUTE_TYPE_VALUE`


    .. attribute:: DigestAlgorithm

        :class:`CRYPT_ALGORITHM_IDENTIFIER`


    .. attribute:: Digest

        :class:`CRYPT_HASH_BLOB`

CRYPTCATMEMBER_
'''''''''''''''
.. class:: CRYPTCATMEMBER

    Alias for :class:`CRYPTCATMEMBER_`

.. class:: PCRYPTCATMEMBER

    Pointer to :class:`CRYPTCATMEMBER_`

.. class:: CRYPTCATMEMBER_

    .. attribute:: cbStruct

        :class:`DWORD`


    .. attribute:: pwszReferenceTag

        :class:`LPWSTR`


    .. attribute:: pwszFileName

        :class:`LPWSTR`


    .. attribute:: gSubjectType

        :class:`GUID`


    .. attribute:: fdwMemberFlags

        :class:`DWORD`


    .. attribute:: pIndirectData

        :class:`SIP_INDIRECT_DATA`


    .. attribute:: dwCertVersion

        :class:`DWORD`


    .. attribute:: dwReserved

        :class:`DWORD`


    .. attribute:: hReserved

        :class:`HANDLE`


    .. attribute:: sEncodedIndirectData

        :class:`CRYPT_ATTR_BLOB`


    .. attribute:: sEncodedMemberInfo

        :class:`CRYPT_ATTR_BLOB`

WINTRUST_FILE_INFO_
'''''''''''''''''''
.. class:: WINTRUST_FILE_INFO

    Alias for :class:`WINTRUST_FILE_INFO_`

.. class:: PWINTRUST_FILE_INFO

    Pointer to :class:`WINTRUST_FILE_INFO_`

.. class:: WINTRUST_FILE_INFO_

    .. attribute:: cbStruct

        :class:`DWORD`


    .. attribute:: pcwszFilePath

        :class:`LPCWSTR`


    .. attribute:: hFile

        :class:`HANDLE`


    .. attribute:: pgKnownSubject

        :class:`GUID`

_CRYPT_ATTRIBUTE
''''''''''''''''
.. class:: PCRYPT_ATTRIBUTE

    Pointer to :class:`_CRYPT_ATTRIBUTE`

.. class:: CRYPT_ATTRIBUTE

    Alias for :class:`_CRYPT_ATTRIBUTE`

.. class:: _CRYPT_ATTRIBUTE

    .. attribute:: pszObjId

        :class:`LPSTR`


    .. attribute:: cValue

        :class:`DWORD`


    .. attribute:: rgValue

        :class:`PCRYPT_ATTR_BLOB`

_CTL_ENTRY
''''''''''
.. class:: PCTL_ENTRY

    Pointer to :class:`_CTL_ENTRY`

.. class:: CTL_ENTRY

    Alias for :class:`_CTL_ENTRY`

.. class:: _CTL_ENTRY

    .. attribute:: SubjectIdentifier

        :class:`CRYPT_DATA_BLOB`


    .. attribute:: cAttribute

        :class:`DWORD`


    .. attribute:: rgAttribute

        :class:`PCRYPT_ATTRIBUTE`

_CRYPT_ATTRIBUTE
''''''''''''''''
.. class:: PCRYPT_ATTRIBUTE

    Pointer to :class:`_CRYPT_ATTRIBUTE`

.. class:: CRYPT_ATTRIBUTE

    Alias for :class:`_CRYPT_ATTRIBUTE`

.. class:: _CRYPT_ATTRIBUTE

    .. attribute:: pszObjId

        :class:`LPSTR`


    .. attribute:: cValue

        :class:`DWORD`


    .. attribute:: rgValue

        :class:`PCRYPT_ATTR_BLOB`

_CRYPT_ATTRIBUTES
'''''''''''''''''
.. class:: CRYPT_ATTRIBUTES

    Alias for :class:`_CRYPT_ATTRIBUTES`

.. class:: PCRYPT_ATTRIBUTES

    Pointer to :class:`_CRYPT_ATTRIBUTES`

.. class:: _CRYPT_ATTRIBUTES

    .. attribute:: cAttr

        :class:`DWORD`


    .. attribute:: rgAttr

        :class:`PCRYPT_ATTRIBUTE`

_CMSG_SIGNER_INFO
'''''''''''''''''
.. class:: CMSG_SIGNER_INFO

    Alias for :class:`_CMSG_SIGNER_INFO`

.. class:: PCMSG_SIGNER_INFO

    Pointer to :class:`_CMSG_SIGNER_INFO`

.. class:: _CMSG_SIGNER_INFO

    .. attribute:: dwVersion

        :class:`DWORD`


    .. attribute:: Issuer

        :class:`CERT_NAME_BLOB`


    .. attribute:: SerialNumber

        :class:`CRYPT_INTEGER_BLOB`


    .. attribute:: HashAlgorithm

        :class:`CRYPT_ALGORITHM_IDENTIFIER`


    .. attribute:: HashEncryptionAlgorithm

        :class:`CRYPT_ALGORITHM_IDENTIFIER`


    .. attribute:: EncryptedHash

        :class:`CRYPT_DATA_BLOB`


    .. attribute:: AuthAttrs

        :class:`CRYPT_ATTRIBUTES`


    .. attribute:: UnauthAttrs

        :class:`CRYPT_ATTRIBUTES`

_CERT_EXTENSION
'''''''''''''''
.. class:: CERT_EXTENSION

    Alias for :class:`_CERT_EXTENSION`

.. class:: PCERT_EXTENSION

    Pointer to :class:`_CERT_EXTENSION`

.. class:: _CERT_EXTENSION

    .. attribute:: pszObjId

        :class:`LPSTR`


    .. attribute:: fCritical

        :class:`BOOL`


    .. attribute:: Value

        :class:`CRYPT_OBJID_BLOB`

_CTL_USAGE
''''''''''
.. class:: CERT_ENHKEY_USAGE

    Alias for :class:`_CTL_USAGE`

.. class:: PCTL_USAGE

    Pointer to :class:`_CTL_USAGE`

.. class:: CTL_USAGE

    Alias for :class:`_CTL_USAGE`

.. class:: PCERT_ENHKEY_USAGE

    Pointer to :class:`_CTL_USAGE`

.. class:: _CTL_USAGE

    .. attribute:: cUsageIdentifier

        :class:`DWORD`


    .. attribute:: rgpszUsageIdentifier

        :class:`LPSTR`

_CTL_INFO
'''''''''
.. class:: CTL_INFO

    Alias for :class:`_CTL_INFO`

.. class:: PCTL_INFO

    Pointer to :class:`_CTL_INFO`

.. class:: _CTL_INFO

    .. attribute:: dwVersion

        :class:`DWORD`


    .. attribute:: SubjectUsage

        :class:`CTL_USAGE`


    .. attribute:: ListIdentifier

        :class:`CRYPT_DATA_BLOB`


    .. attribute:: SequenceNumber

        :class:`CRYPT_INTEGER_BLOB`


    .. attribute:: ThisUpdate

        :class:`FILETIME`


    .. attribute:: NextUpdate

        :class:`FILETIME`


    .. attribute:: SubjectAlgorithm

        :class:`CRYPT_ALGORITHM_IDENTIFIER`


    .. attribute:: cCTLEntry

        :class:`DWORD`


    .. attribute:: rgCTLEntry

        :class:`PCTL_ENTRY`


    .. attribute:: cExtension

        :class:`DWORD`


    .. attribute:: rgExtension

        :class:`PCERT_EXTENSION`

_CTL_CONTEXT
''''''''''''
.. class:: PCTL_CONTEXT

    Pointer to :class:`_CTL_CONTEXT`

.. class:: CTL_CONTEXT

    Alias for :class:`_CTL_CONTEXT`

.. class:: PCCTL_CONTEXT

    Pointer to :class:`_CTL_CONTEXT`

.. class:: _CTL_CONTEXT

    .. attribute:: dwMsgAndCertEncodingType

        :class:`DWORD`


    .. attribute:: pbCtlEncoded

        :class:`BYTE`


    .. attribute:: cbCtlEncoded

        :class:`DWORD`


    .. attribute:: pCtlInfo

        :class:`PCTL_INFO`


    .. attribute:: hCertStore

        :class:`HCERTSTORE`


    .. attribute:: hCryptMsg

        :class:`HCRYPTMSG`


    .. attribute:: pbCtlContent

        :class:`BYTE`


    .. attribute:: cbCtlContent

        :class:`DWORD`

WINTRUST_CATALOG_INFO_
''''''''''''''''''''''
.. class:: PWINTRUST_CATALOG_INFO

    Pointer to :class:`WINTRUST_CATALOG_INFO_`

.. class:: WINTRUST_CATALOG_INFO

    Alias for :class:`WINTRUST_CATALOG_INFO_`

.. class:: WINTRUST_CATALOG_INFO_

    .. attribute:: cbStruct

        :class:`DWORD`


    .. attribute:: dwCatalogVersion

        :class:`DWORD`


    .. attribute:: pcwszCatalogFilePath

        :class:`LPCWSTR`


    .. attribute:: pcwszMemberTag

        :class:`LPCWSTR`


    .. attribute:: pcwszMemberFilePath

        :class:`LPCWSTR`


    .. attribute:: hMemberFile

        :class:`HANDLE`


    .. attribute:: pbCalculatedFileHash

        :class:`BYTE`


    .. attribute:: cbCalculatedFileHash

        :class:`DWORD`


    .. attribute:: pcCatalogContext

        :class:`PCCTL_CONTEXT`

WINTRUST_BLOB_INFO_
'''''''''''''''''''
.. class:: PWINTRUST_BLOB_INFO

    Pointer to :class:`WINTRUST_BLOB_INFO_`

.. class:: WINTRUST_BLOB_INFO

    Alias for :class:`WINTRUST_BLOB_INFO_`

.. class:: WINTRUST_BLOB_INFO_

    .. attribute:: cbStruct

        :class:`DWORD`


    .. attribute:: gSubject

        :class:`GUID`


    .. attribute:: pcwszDisplayName

        :class:`LPCWSTR`


    .. attribute:: cbMemObject

        :class:`DWORD`


    .. attribute:: pbMemObject

        :class:`BYTE`


    .. attribute:: cbMemSignedMsg

        :class:`DWORD`


    .. attribute:: pbMemSignedMsg

        :class:`BYTE`

_CRYPT_BIT_BLOB
'''''''''''''''
.. class:: CRYPT_BIT_BLOB

    Alias for :class:`_CRYPT_BIT_BLOB`

.. class:: PCRYPT_BIT_BLOB

    Pointer to :class:`_CRYPT_BIT_BLOB`

.. class:: _CRYPT_BIT_BLOB

    .. attribute:: cbData

        :class:`DWORD`


    .. attribute:: pbData

        :class:`BYTE`


    .. attribute:: cUnusedBits

        :class:`DWORD`

_CERT_PUBLIC_KEY_INFO
'''''''''''''''''''''
.. class:: PCERT_PUBLIC_KEY_INFO

    Pointer to :class:`_CERT_PUBLIC_KEY_INFO`

.. class:: CERT_PUBLIC_KEY_INFO

    Alias for :class:`_CERT_PUBLIC_KEY_INFO`

.. class:: _CERT_PUBLIC_KEY_INFO

    .. attribute:: Algorithm

        :class:`CRYPT_ALGORITHM_IDENTIFIER`


    .. attribute:: PublicKey

        :class:`CRYPT_BIT_BLOB`

_CERT_INFO
''''''''''
.. class:: CERT_INFO

    Alias for :class:`_CERT_INFO`

.. class:: PCERT_INFO

    Pointer to :class:`_CERT_INFO`

.. class:: _CERT_INFO

    .. attribute:: dwVersion

        :class:`DWORD`


    .. attribute:: SerialNumber

        :class:`CRYPT_INTEGER_BLOB`


    .. attribute:: SignatureAlgorithm

        :class:`CRYPT_ALGORITHM_IDENTIFIER`


    .. attribute:: Issuer

        :class:`CERT_NAME_BLOB`


    .. attribute:: NotBefore

        :class:`FILETIME`


    .. attribute:: NotAfter

        :class:`FILETIME`


    .. attribute:: Subject

        :class:`CERT_NAME_BLOB`


    .. attribute:: SubjectPublicKeyInfo

        :class:`CERT_PUBLIC_KEY_INFO`


    .. attribute:: IssuerUniqueId

        :class:`CRYPT_BIT_BLOB`


    .. attribute:: SubjectUniqueId

        :class:`CRYPT_BIT_BLOB`


    .. attribute:: cExtension

        :class:`DWORD`


    .. attribute:: rgExtension

        :class:`PCERT_EXTENSION`

_CERT_CONTEXT
'''''''''''''
.. class:: CERT_CONTEXT

    Alias for :class:`_CERT_CONTEXT`

.. class:: PCERT_CONTEXT

    Pointer to :class:`_CERT_CONTEXT`

.. class:: _CERT_CONTEXT

    .. attribute:: dwCertEncodingType

        :class:`DWORD`


    .. attribute:: pbCertEncoded

        :class:`BYTE`


    .. attribute:: cbCertEncoded

        :class:`DWORD`


    .. attribute:: pCertInfo

        :class:`PCERT_INFO`


    .. attribute:: hCertStore

        :class:`HCERTSTORE`

WINTRUST_SGNR_INFO_
'''''''''''''''''''
.. class:: WINTRUST_SGNR_INFO

    Alias for :class:`WINTRUST_SGNR_INFO_`

.. class:: PWINTRUST_SGNR_INFO

    Pointer to :class:`WINTRUST_SGNR_INFO_`

.. class:: WINTRUST_SGNR_INFO_

    .. attribute:: cbStruct

        :class:`DWORD`


    .. attribute:: pcwszDisplayName

        :class:`LPCWSTR`


    .. attribute:: psSignerInfo

        :class:`CMSG_SIGNER_INFO`


    .. attribute:: chStores

        :class:`DWORD`


    .. attribute:: pahStores

        :class:`HCERTSTORE`

WINTRUST_CERT_INFO_
'''''''''''''''''''
.. class:: WINTRUST_CERT_INFO

    Alias for :class:`WINTRUST_CERT_INFO_`

.. class:: PWINTRUST_CERT_INFO

    Pointer to :class:`WINTRUST_CERT_INFO_`

.. class:: WINTRUST_CERT_INFO_

    .. attribute:: cbStruct

        :class:`DWORD`


    .. attribute:: pcwszDisplayName

        :class:`LPCWSTR`


    .. attribute:: psCertContext

        :class:`CERT_CONTEXT`


    .. attribute:: chStores

        :class:`DWORD`


    .. attribute:: pahStores

        :class:`HCERTSTORE`


    .. attribute:: dwFlags

        :class:`DWORD`


    .. attribute:: psftVerifyAsOf

        :class:`FILETIME`

_TMP_WINTRUST_UNION_TYPE
''''''''''''''''''''''''
.. class:: TMP_WINTRUST_UNION_TYPE

    Alias for :class:`_TMP_WINTRUST_UNION_TYPE`

.. class:: _TMP_WINTRUST_UNION_TYPE

    .. attribute:: pFile

        :class:`WINTRUST_FILE_INFO_`


    .. attribute:: pCatalog

        :class:`WINTRUST_CATALOG_INFO_`


    .. attribute:: pBlob

        :class:`WINTRUST_BLOB_INFO_`


    .. attribute:: pSgnr

        :class:`WINTRUST_SGNR_INFO_`


    .. attribute:: pCert

        :class:`WINTRUST_CERT_INFO_`

_WINTRUST_DATA
''''''''''''''
.. class:: PWINTRUST_DATA

    Pointer to :class:`_WINTRUST_DATA`

.. class:: WINTRUST_DATA

    Alias for :class:`_WINTRUST_DATA`

.. class:: _WINTRUST_DATA

    .. attribute:: cbStruct

        :class:`DWORD`


    .. attribute:: pPolicyCallbackData

        :class:`LPVOID`


    .. attribute:: pSIPClientData

        :class:`LPVOID`


    .. attribute:: dwUIChoice

        :class:`DWORD`


    .. attribute:: fdwRevocationChecks

        :class:`DWORD`


    .. attribute:: dwUnionChoice

        :class:`DWORD`


    .. attribute:: tmp_union

        :class:`TMP_WINTRUST_UNION_TYPE`


    .. attribute:: dwStateAction

        :class:`DWORD`


    .. attribute:: hWVTStateData

        :class:`HANDLE`


    .. attribute:: pwszURLReference

        :class:`WCHAR`


    .. attribute:: dwProvFlags

        :class:`DWORD`


    .. attribute:: dwUIContext

        :class:`DWORD`

_PROCESS_BASIC_INFORMATION
''''''''''''''''''''''''''
.. class:: PPROCESS_BASIC_INFORMATION

    Pointer to :class:`_PROCESS_BASIC_INFORMATION`

.. class:: PROCESS_BASIC_INFORMATION

    Alias for :class:`_PROCESS_BASIC_INFORMATION`

.. class:: _PROCESS_BASIC_INFORMATION

    .. attribute:: ExitStatus

        :class:`NTSTATUS`


    .. attribute:: PebBaseAddress

        :class:`PPEB`


    .. attribute:: AffinityMask

        :class:`ULONG_PTR`


    .. attribute:: BasePriority

        :class:`KPRIORITY`


    .. attribute:: UniqueProcessId

        :class:`HANDLE`


    .. attribute:: InheritedFromUniqueProcessId

        :class:`HANDLE`

_JIT_DEBUG_INFO
'''''''''''''''
.. class:: LPJIT_DEBUG_INFO

    Pointer to :class:`_JIT_DEBUG_INFO`

.. class:: JIT_DEBUG_INFO

    Alias for :class:`_JIT_DEBUG_INFO`

.. class:: _JIT_DEBUG_INFO

    .. attribute:: dwSize

        :class:`DWORD`


    .. attribute:: dwProcessorArchitecture

        :class:`DWORD`


    .. attribute:: dwThreadID

        :class:`DWORD`


    .. attribute:: dwReserved0

        :class:`DWORD`


    .. attribute:: lpExceptionAddress

        :class:`ULONG64`


    .. attribute:: lpExceptionRecord

        :class:`ULONG64`


    .. attribute:: lpContextRecord

        :class:`ULONG64`

_SID_IDENTIFIER_AUTHORITY
'''''''''''''''''''''''''
.. class:: SID_IDENTIFIER_AUTHORITY

    Alias for :class:`_SID_IDENTIFIER_AUTHORITY`

.. class:: PSID_IDENTIFIER_AUTHORITY

    Pointer to :class:`_SID_IDENTIFIER_AUTHORITY`

.. class:: _SID_IDENTIFIER_AUTHORITY

    .. attribute:: Value

        :class:`BYTE` ``[6]``

_EXCEPTION_DEBUG_INFO
'''''''''''''''''''''
.. class:: LPEXCEPTION_DEBUG_INFO

    Pointer to :class:`_EXCEPTION_DEBUG_INFO`

.. class:: EXCEPTION_DEBUG_INFO

    Alias for :class:`_EXCEPTION_DEBUG_INFO`

.. class:: _EXCEPTION_DEBUG_INFO

    .. attribute:: ExceptionRecord

        :class:`EXCEPTION_RECORD`


    .. attribute:: dwFirstChance

        :class:`DWORD`

_CREATE_THREAD_DEBUG_INFO
'''''''''''''''''''''''''
.. class:: LPCREATE_THREAD_DEBUG_INFO

    Pointer to :class:`_CREATE_THREAD_DEBUG_INFO`

.. class:: CREATE_THREAD_DEBUG_INFO

    Alias for :class:`_CREATE_THREAD_DEBUG_INFO`

.. class:: _CREATE_THREAD_DEBUG_INFO

    .. attribute:: hThread

        :class:`HANDLE`


    .. attribute:: lpThreadLocalBase

        :class:`LPVOID`


    .. attribute:: lpStartAddress

        :class:`LPTHREAD_START_ROUTINE`

_CREATE_PROCESS_DEBUG_INFO
''''''''''''''''''''''''''
.. class:: CREATE_PROCESS_DEBUG_INFO

    Alias for :class:`_CREATE_PROCESS_DEBUG_INFO`

.. class:: LPCREATE_PROCESS_DEBUG_INFO

    Pointer to :class:`_CREATE_PROCESS_DEBUG_INFO`

.. class:: _CREATE_PROCESS_DEBUG_INFO

    .. attribute:: hFile

        :class:`HANDLE`


    .. attribute:: hProcess

        :class:`HANDLE`


    .. attribute:: hThread

        :class:`HANDLE`


    .. attribute:: lpBaseOfImage

        :class:`LPVOID`


    .. attribute:: dwDebugInfoFileOffset

        :class:`DWORD`


    .. attribute:: nDebugInfoSize

        :class:`DWORD`


    .. attribute:: lpThreadLocalBase

        :class:`LPVOID`


    .. attribute:: lpStartAddress

        :class:`LPTHREAD_START_ROUTINE`


    .. attribute:: lpImageName

        :class:`LPVOID`


    .. attribute:: fUnicode

        :class:`WORD`

_EXIT_THREAD_DEBUG_INFO
'''''''''''''''''''''''
.. class:: EXIT_THREAD_DEBUG_INFO

    Alias for :class:`_EXIT_THREAD_DEBUG_INFO`

.. class:: LPEXIT_THREAD_DEBUG_INFO

    Pointer to :class:`_EXIT_THREAD_DEBUG_INFO`

.. class:: _EXIT_THREAD_DEBUG_INFO

    .. attribute:: dwExitCode

        :class:`DWORD`

_EXIT_PROCESS_DEBUG_INFO
''''''''''''''''''''''''
.. class:: LPEXIT_PROCESS_DEBUG_INFO

    Pointer to :class:`_EXIT_PROCESS_DEBUG_INFO`

.. class:: EXIT_PROCESS_DEBUG_INFO

    Alias for :class:`_EXIT_PROCESS_DEBUG_INFO`

.. class:: _EXIT_PROCESS_DEBUG_INFO

    .. attribute:: dwExitCode

        :class:`DWORD`

_LOAD_DLL_DEBUG_INFO
''''''''''''''''''''
.. class:: LPLOAD_DLL_DEBUG_INFO

    Pointer to :class:`_LOAD_DLL_DEBUG_INFO`

.. class:: LOAD_DLL_DEBUG_INFO

    Alias for :class:`_LOAD_DLL_DEBUG_INFO`

.. class:: _LOAD_DLL_DEBUG_INFO

    .. attribute:: hFile

        :class:`HANDLE`


    .. attribute:: lpBaseOfDll

        :class:`LPVOID`


    .. attribute:: dwDebugInfoFileOffset

        :class:`DWORD`


    .. attribute:: nDebugInfoSize

        :class:`DWORD`


    .. attribute:: lpImageName

        :class:`LPVOID`


    .. attribute:: fUnicode

        :class:`WORD`

_UNLOAD_DLL_DEBUG_INFO
''''''''''''''''''''''
.. class:: UNLOAD_DLL_DEBUG_INFO

    Alias for :class:`_UNLOAD_DLL_DEBUG_INFO`

.. class:: LPUNLOAD_DLL_DEBUG_INFO

    Pointer to :class:`_UNLOAD_DLL_DEBUG_INFO`

.. class:: _UNLOAD_DLL_DEBUG_INFO

    .. attribute:: lpBaseOfDll

        :class:`LPVOID`

_OUTPUT_DEBUG_STRING_INFO
'''''''''''''''''''''''''
.. class:: OUTPUT_DEBUG_STRING_INFO

    Alias for :class:`_OUTPUT_DEBUG_STRING_INFO`

.. class:: LPOUTPUT_DEBUG_STRING_INFO

    Pointer to :class:`_OUTPUT_DEBUG_STRING_INFO`

.. class:: _OUTPUT_DEBUG_STRING_INFO

    .. attribute:: lpDebugStringData

        :class:`LPSTR`


    .. attribute:: fUnicode

        :class:`WORD`


    .. attribute:: nDebugStringLength

        :class:`WORD`

_RIP_INFO
'''''''''
.. class:: LPRIP_INFO

    Pointer to :class:`_RIP_INFO`

.. class:: RIP_INFO

    Alias for :class:`_RIP_INFO`

.. class:: _RIP_INFO

    .. attribute:: dwError

        :class:`DWORD`


    .. attribute:: dwType

        :class:`DWORD`

_TMP_UNION_DEBUG_INFO
'''''''''''''''''''''
.. class:: TMP_UNION_DEBUG_INFO

    Alias for :class:`_TMP_UNION_DEBUG_INFO`

.. class:: _TMP_UNION_DEBUG_INFO

    .. attribute:: Exception

        :class:`EXCEPTION_DEBUG_INFO`


    .. attribute:: CreateThread

        :class:`CREATE_THREAD_DEBUG_INFO`


    .. attribute:: CreateProcessInfo

        :class:`CREATE_PROCESS_DEBUG_INFO`


    .. attribute:: ExitThread

        :class:`EXIT_THREAD_DEBUG_INFO`


    .. attribute:: ExitProcess

        :class:`EXIT_PROCESS_DEBUG_INFO`


    .. attribute:: LoadDll

        :class:`LOAD_DLL_DEBUG_INFO`


    .. attribute:: UnloadDll

        :class:`UNLOAD_DLL_DEBUG_INFO`


    .. attribute:: DebugString

        :class:`OUTPUT_DEBUG_STRING_INFO`


    .. attribute:: RipInfo

        :class:`RIP_INFO`

_DEBUG_EVENT
''''''''''''
.. class:: LPDEBUG_EVENT

    Pointer to :class:`_DEBUG_EVENT`

.. class:: DEBUG_EVENT

    Alias for :class:`_DEBUG_EVENT`

.. class:: _DEBUG_EVENT

    .. attribute:: dwDebugEventCode

        :class:`DWORD`


    .. attribute:: dwProcessId

        :class:`DWORD`


    .. attribute:: dwThreadId

        :class:`DWORD`


    .. attribute:: u

        :class:`_TMP_UNION_DEBUG_INFO`

_STRING
'''''''
.. class:: PCANSI_STRING

    Pointer to :class:`_STRING`

.. class:: PSTRING

    Pointer to :class:`_STRING`

.. class:: STRING

    Alias for :class:`_STRING`

.. class:: PANSI_STRING

    Pointer to :class:`_STRING`

.. class:: _STRING

    .. attribute:: Length

        :class:`USHORT`


    .. attribute:: MaximumLength

        :class:`USHORT`


    .. attribute:: Buffer

        :class:`LPCSTR`

_OBJECT_ATTRIBUTES
''''''''''''''''''
.. class:: POBJECT_ATTRIBUTES

    Pointer to :class:`_OBJECT_ATTRIBUTES`

.. class:: OBJECT_ATTRIBUTES

    Alias for :class:`_OBJECT_ATTRIBUTES`

.. class:: _OBJECT_ATTRIBUTES

    .. attribute:: Length

        :class:`ULONG`


    .. attribute:: RootDirectory

        :class:`HANDLE`


    .. attribute:: ObjectName

        :class:`PUNICODE_STRING`


    .. attribute:: Attributes

        :class:`ULONG`


    .. attribute:: SecurityDescriptor

        :class:`PVOID`


    .. attribute:: SecurityQualityOfService

        :class:`PVOID`

_TMP_UNION_IO_STATUS_BLOCK
''''''''''''''''''''''''''
.. class:: TMP_UNION_IO_STATUS_BLOCK

    Alias for :class:`_TMP_UNION_IO_STATUS_BLOCK`

.. class:: _TMP_UNION_IO_STATUS_BLOCK

    .. attribute:: Status

        :class:`NTSTATUS`


    .. attribute:: Pointer

        :class:`PVOID`

_IO_STATUS_BLOCK
''''''''''''''''
.. class:: IO_STATUS_BLOCK

    Alias for :class:`_IO_STATUS_BLOCK`

.. class:: PIO_STATUS_BLOCK

    Pointer to :class:`_IO_STATUS_BLOCK`

.. class:: _IO_STATUS_BLOCK

    .. attribute:: DUMMYUNIONNAME

        :class:`TMP_UNION_IO_STATUS_BLOCK`


    .. attribute:: Information

        :class:`ULONG_PTR`

_SECURITY_QUALITY_OF_SERVICE
''''''''''''''''''''''''''''
.. class:: PSECURITY_QUALITY_OF_SERVICE

    Pointer to :class:`_SECURITY_QUALITY_OF_SERVICE`

.. class:: SECURITY_QUALITY_OF_SERVICE

    Alias for :class:`_SECURITY_QUALITY_OF_SERVICE`

.. class:: _SECURITY_QUALITY_OF_SERVICE

    .. attribute:: Length

        :class:`DWORD`


    .. attribute:: ImpersonationLevel

        :class:`SECURITY_IMPERSONATION_LEVEL`


    .. attribute:: ContextTrackingMode

        :class:`SECURITY_CONTEXT_TRACKING_MODE`


    .. attribute:: EffectiveOnly

        :class:`BOOLEAN`

_SERVICE_STATUS
'''''''''''''''
.. class:: SERVICE_STATUS

    Alias for :class:`_SERVICE_STATUS`

.. class:: LPSERVICE_STATUS

    Pointer to :class:`_SERVICE_STATUS`

.. class:: _SERVICE_STATUS

    .. attribute:: dwServiceType

        :class:`DWORD`


    .. attribute:: dwCurrentState

        :class:`DWORD`


    .. attribute:: dwControlsAccepted

        :class:`DWORD`


    .. attribute:: dwWin32ExitCode

        :class:`DWORD`


    .. attribute:: dwServiceSpecificExitCode

        :class:`DWORD`


    .. attribute:: dwCheckPoint

        :class:`DWORD`


    .. attribute:: dwWaitHint

        :class:`DWORD`

_SERVICE_STATUS_PROCESS
'''''''''''''''''''''''
.. class:: LPSERVICE_STATUS_PROCESS

    Pointer to :class:`_SERVICE_STATUS_PROCESS`

.. class:: SERVICE_STATUS_PROCESS

    Alias for :class:`_SERVICE_STATUS_PROCESS`

.. class:: _SERVICE_STATUS_PROCESS

    .. attribute:: dwServiceType

        :class:`DWORD`


    .. attribute:: dwCurrentState

        :class:`DWORD`


    .. attribute:: dwControlsAccepted

        :class:`DWORD`


    .. attribute:: dwWin32ExitCode

        :class:`DWORD`


    .. attribute:: dwServiceSpecificExitCode

        :class:`DWORD`


    .. attribute:: dwCheckPoint

        :class:`DWORD`


    .. attribute:: dwWaitHint

        :class:`DWORD`


    .. attribute:: dwProcessId

        :class:`DWORD`


    .. attribute:: dwServiceFlags

        :class:`DWORD`

_ENUM_SERVICE_STATUS_PROCESSA
'''''''''''''''''''''''''''''
.. class:: LPENUM_SERVICE_STATUS_PROCESSA

    Pointer to :class:`_ENUM_SERVICE_STATUS_PROCESSA`

.. class:: ENUM_SERVICE_STATUS_PROCESSA

    Alias for :class:`_ENUM_SERVICE_STATUS_PROCESSA`

.. class:: _ENUM_SERVICE_STATUS_PROCESSA

    .. attribute:: lpServiceName

        :class:`LPSTR`


    .. attribute:: lpDisplayName

        :class:`LPSTR`


    .. attribute:: ServiceStatusProcess

        :class:`SERVICE_STATUS_PROCESS`

_ENUM_SERVICE_STATUS_PROCESSW
'''''''''''''''''''''''''''''
.. class:: ENUM_SERVICE_STATUS_PROCESSW

    Alias for :class:`_ENUM_SERVICE_STATUS_PROCESSW`

.. class:: LPENUM_SERVICE_STATUS_PROCESSW

    Pointer to :class:`_ENUM_SERVICE_STATUS_PROCESSW`

.. class:: _ENUM_SERVICE_STATUS_PROCESSW

    .. attribute:: lpServiceName

        :class:`LPWSTR`


    .. attribute:: lpDisplayName

        :class:`LPWSTR`


    .. attribute:: ServiceStatusProcess

        :class:`SERVICE_STATUS_PROCESS`

CATALOG_INFO_
'''''''''''''
.. class:: CATALOG_INFO

    Alias for :class:`CATALOG_INFO_`

.. class:: CATALOG_INFO_

    .. attribute:: cbStruct

        :class:`DWORD`


    .. attribute:: wszCatalogFile

        :class:`WCHAR` ``[MAX_PATH]``

_SYSTEM_HANDLE
''''''''''''''
.. class:: SYSTEM_HANDLE

    Alias for :class:`_SYSTEM_HANDLE`

.. class:: _SYSTEM_HANDLE

    .. attribute:: dwProcessId

        :class:`DWORD`


    .. attribute:: bObjectType

        :class:`BYTE`


    .. attribute:: bFlags

        :class:`BYTE`


    .. attribute:: wValue

        :class:`WORD`


    .. attribute:: pAddress

        :class:`PVOID`


    .. attribute:: GrantedAccess

        :class:`DWORD`

_SYSTEM_HANDLE_INFORMATION
''''''''''''''''''''''''''
.. class:: PSYSTEM_HANDLE_INFORMATION

    Pointer to :class:`_SYSTEM_HANDLE_INFORMATION`

.. class:: SYSTEM_HANDLE_INFORMATION

    Alias for :class:`_SYSTEM_HANDLE_INFORMATION`

.. class:: _SYSTEM_HANDLE_INFORMATION

    .. attribute:: HandleCount

        :class:`ULONG`


    .. attribute:: Handles

        :class:`SYSTEM_HANDLE` ``[1]``

__PUBLIC_OBJECT_TYPE_INFORMATION
''''''''''''''''''''''''''''''''
.. class:: PPUBLIC_OBJECT_TYPE_INFORMATION

    Pointer to :class:`__PUBLIC_OBJECT_TYPE_INFORMATION`

.. class:: PUBLIC_OBJECT_TYPE_INFORMATION

    Alias for :class:`__PUBLIC_OBJECT_TYPE_INFORMATION`

.. class:: __PUBLIC_OBJECT_TYPE_INFORMATION

    .. attribute:: TypeName

        :class:`UNICODE_STRING`


    .. attribute:: Reserved

        :class:`ULONG` ``[22]``

_PUBLIC_OBJECT_BASIC_INFORMATION
''''''''''''''''''''''''''''''''
.. class:: PUBLIC_OBJECT_BASIC_INFORMATION

    Alias for :class:`_PUBLIC_OBJECT_BASIC_INFORMATION`

.. class:: PPUBLIC_OBJECT_BASIC_INFORMATION

    Pointer to :class:`_PUBLIC_OBJECT_BASIC_INFORMATION`

.. class:: _PUBLIC_OBJECT_BASIC_INFORMATION

    .. attribute:: Attributes

        :class:`ULONG`


    .. attribute:: GrantedAccess

        :class:`ACCESS_MASK`


    .. attribute:: HandleCount

        :class:`ULONG`


    .. attribute:: PointerCount

        :class:`ULONG`


    .. attribute:: Reserved

        :class:`ULONG` ``[10]``

tagSOLE_AUTHENTICATION_SERVICE
''''''''''''''''''''''''''''''
.. class:: PSOLE_AUTHENTICATION_SERVICE

    Pointer to :class:`tagSOLE_AUTHENTICATION_SERVICE`

.. class:: SOLE_AUTHENTICATION_SERVICE

    Alias for :class:`tagSOLE_AUTHENTICATION_SERVICE`

.. class:: tagSOLE_AUTHENTICATION_SERVICE

    .. attribute:: dwAuthnSvc

        :class:`DWORD`


    .. attribute:: dwAuthzSvc

        :class:`DWORD`


    .. attribute:: pPrincipalName

        :class:`OLECHAR`


    .. attribute:: hr

        :class:`HRESULT`

_OBJECT_DIRECTORY_INFORMATION
'''''''''''''''''''''''''''''
.. class:: OBJECT_DIRECTORY_INFORMATION

    Alias for :class:`_OBJECT_DIRECTORY_INFORMATION`

.. class:: POBJECT_DIRECTORY_INFORMATION

    Pointer to :class:`_OBJECT_DIRECTORY_INFORMATION`

.. class:: _OBJECT_DIRECTORY_INFORMATION

    .. attribute:: Name

        :class:`UNICODE_STRING`


    .. attribute:: TypeName

        :class:`UNICODE_STRING`

_DEBUG_VALUE_TMP_SUBSTRUCT1
'''''''''''''''''''''''''''
.. class:: DEBUG_VALUE_TMP_SUBSTRUCT1

    Alias for :class:`_DEBUG_VALUE_TMP_SUBSTRUCT1`

.. class:: _DEBUG_VALUE_TMP_SUBSTRUCT1

    .. attribute:: I64

        :class:`ULONG64`


    .. attribute:: Nat

        :class:`BOOL`

_DEBUG_VALUE_TMP_SUBSTRUCT2
'''''''''''''''''''''''''''
.. class:: DEBUG_VALUE_TMP_SUBSTRUCT2

    Alias for :class:`_DEBUG_VALUE_TMP_SUBSTRUCT2`

.. class:: _DEBUG_VALUE_TMP_SUBSTRUCT2

    .. attribute:: LowPart

        :class:`ULONG`


    .. attribute:: HighPart

        :class:`ULONG`

_DEBUG_VALUE_TMP_SUBSTRUCT3
'''''''''''''''''''''''''''
.. class:: DEBUG_VALUE_TMP_SUBSTRUCT3

    Alias for :class:`_DEBUG_VALUE_TMP_SUBSTRUCT3`

.. class:: _DEBUG_VALUE_TMP_SUBSTRUCT3

    .. attribute:: LowPart

        :class:`ULONG64`


    .. attribute:: HighPart

        :class:`LONG64`

_DEBUG_VALUE_TMP_UNION
''''''''''''''''''''''
.. class:: DEBUG_VALUE_TMP_UNION

    Alias for :class:`_DEBUG_VALUE_TMP_UNION`

.. class:: _DEBUG_VALUE_TMP_UNION

    .. attribute:: I8

        :class:`UCHAR`


    .. attribute:: I16

        :class:`USHORT`


    .. attribute:: I32

        :class:`ULONG`


    .. attribute:: tmp_sub_struct_1

        :class:`_DEBUG_VALUE_TMP_SUBSTRUCT1`


    .. attribute:: F32

        :class:`FLOAT`


    .. attribute:: F64

        :class:`DOUBLE`


    .. attribute:: F80Bytes

        :class:`UCHAR` ``[10]``


    .. attribute:: F82Bytes

        :class:`UCHAR` ``[11]``


    .. attribute:: F128Bytes

        :class:`UCHAR` ``[16]``


    .. attribute:: VI8

        :class:`UCHAR` ``[16]``


    .. attribute:: VI16

        :class:`USHORT` ``[8]``


    .. attribute:: VI32

        :class:`ULONG` ``[4]``


    .. attribute:: VI64

        :class:`ULONG64` ``[2]``


    .. attribute:: VF32

        :class:`FLOAT` ``[4]``


    .. attribute:: VF64

        :class:`DOUBLE` ``[2]``


    .. attribute:: I64Parts32

        :class:`DEBUG_VALUE_TMP_SUBSTRUCT2`


    .. attribute:: F128Parts64

        :class:`DEBUG_VALUE_TMP_SUBSTRUCT3`


    .. attribute:: RawBytes

        :class:`UCHAR` ``[24]``

_DEBUG_VALUE
''''''''''''
.. class:: DEBUG_VALUE

    Alias for :class:`_DEBUG_VALUE`

.. class:: PDEBUG_VALUE

    Pointer to :class:`_DEBUG_VALUE`

.. class:: _DEBUG_VALUE

    .. attribute:: u

        :class:`_DEBUG_VALUE_TMP_UNION`


    .. attribute:: TailOfRawBytes

        :class:`ULONG`


    .. attribute:: Type

        :class:`ULONG`

_DEBUG_SYMBOL_PARAMETERS
''''''''''''''''''''''''
.. class:: DEBUG_SYMBOL_PARAMETERS

    Alias for :class:`_DEBUG_SYMBOL_PARAMETERS`

.. class:: PDEBUG_SYMBOL_PARAMETERS

    Pointer to :class:`_DEBUG_SYMBOL_PARAMETERS`

.. class:: _DEBUG_SYMBOL_PARAMETERS

    .. attribute:: Module

        :class:`ULONG64`


    .. attribute:: TypeId

        :class:`ULONG`


    .. attribute:: ParentSymbol

        :class:`ULONG`


    .. attribute:: SubElements

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: Reserved

        :class:`ULONG64`

_DEBUG_SYMBOL_ENTRY
'''''''''''''''''''
.. class:: PDEBUG_SYMBOL_ENTRY

    Pointer to :class:`_DEBUG_SYMBOL_ENTRY`

.. class:: DEBUG_SYMBOL_ENTRY

    Alias for :class:`_DEBUG_SYMBOL_ENTRY`

.. class:: _DEBUG_SYMBOL_ENTRY

    .. attribute:: ModuleBase

        :class:`ULONG64`


    .. attribute:: Offset

        :class:`ULONG64`


    .. attribute:: Id

        :class:`ULONG64`


    .. attribute:: Arg64

        :class:`ULONG64`


    .. attribute:: Size

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: TypeId

        :class:`ULONG`


    .. attribute:: NameSize

        :class:`ULONG`


    .. attribute:: Token

        :class:`ULONG`


    .. attribute:: Tag

        :class:`ULONG`


    .. attribute:: Arg32

        :class:`ULONG`


    .. attribute:: Reserved

        :class:`ULONG`

_DEBUG_MODULE_PARAMETERS
''''''''''''''''''''''''
.. class:: PDEBUG_MODULE_PARAMETERS

    Pointer to :class:`_DEBUG_MODULE_PARAMETERS`

.. class:: DEBUG_MODULE_PARAMETERS

    Alias for :class:`_DEBUG_MODULE_PARAMETERS`

.. class:: _DEBUG_MODULE_PARAMETERS

    .. attribute:: Base

        :class:`ULONG64`


    .. attribute:: Size

        :class:`ULONG`


    .. attribute:: TimeDateStamp

        :class:`ULONG`


    .. attribute:: Checksum

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: SymbolType

        :class:`ULONG`


    .. attribute:: ImageNameSize

        :class:`ULONG`


    .. attribute:: ModuleNameSize

        :class:`ULONG`


    .. attribute:: LoadedImageNameSize

        :class:`ULONG`


    .. attribute:: SymbolFileNameSize

        :class:`ULONG`


    .. attribute:: MappedImageNameSize

        :class:`ULONG`


    .. attribute:: Reserved

        :class:`ULONG64` ``[2]``

_DEBUG_MODULE_AND_ID
''''''''''''''''''''
.. class:: DEBUG_MODULE_AND_ID

    Alias for :class:`_DEBUG_MODULE_AND_ID`

.. class:: PDEBUG_MODULE_AND_ID

    Pointer to :class:`_DEBUG_MODULE_AND_ID`

.. class:: _DEBUG_MODULE_AND_ID

    .. attribute:: ModuleBase

        :class:`ULONG64`


    .. attribute:: Id

        :class:`ULONG64`

_DEBUG_OFFSET_REGION
''''''''''''''''''''
.. class:: DEBUG_OFFSET_REGION

    Alias for :class:`_DEBUG_OFFSET_REGION`

.. class:: PDEBUG_OFFSET_REGION

    Pointer to :class:`_DEBUG_OFFSET_REGION`

.. class:: _DEBUG_OFFSET_REGION

    .. attribute:: Base

        :class:`ULONG64`


    .. attribute:: Size

        :class:`ULONG64`

_DEBUG_SYMBOL_SOURCE_ENTRY
''''''''''''''''''''''''''
.. class:: DEBUG_SYMBOL_SOURCE_ENTRY

    Alias for :class:`_DEBUG_SYMBOL_SOURCE_ENTRY`

.. class:: PDEBUG_SYMBOL_SOURCE_ENTRY

    Pointer to :class:`_DEBUG_SYMBOL_SOURCE_ENTRY`

.. class:: _DEBUG_SYMBOL_SOURCE_ENTRY

    .. attribute:: ModuleBase

        :class:`ULONG64`


    .. attribute:: Offset

        :class:`ULONG64`


    .. attribute:: FileNameId

        :class:`ULONG64`


    .. attribute:: EngineInternal

        :class:`ULONG64`


    .. attribute:: Size

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: FileNameSize

        :class:`ULONG`


    .. attribute:: StartLine

        :class:`ULONG`


    .. attribute:: EndLine

        :class:`ULONG`


    .. attribute:: StartColumn

        :class:`ULONG`


    .. attribute:: EndColumn

        :class:`ULONG`


    .. attribute:: Reserved

        :class:`ULONG`

_CMSG_SIGNER_INFO
'''''''''''''''''
.. class:: CMSG_SIGNER_INFO

    Alias for :class:`_CMSG_SIGNER_INFO`

.. class:: PCMSG_SIGNER_INFO

    Pointer to :class:`_CMSG_SIGNER_INFO`

.. class:: _CMSG_SIGNER_INFO

    .. attribute:: dwVersion

        :class:`DWORD`


    .. attribute:: Issuer

        :class:`CERT_NAME_BLOB`


    .. attribute:: SerialNumber

        :class:`CRYPT_INTEGER_BLOB`


    .. attribute:: HashAlgorithm

        :class:`CRYPT_ALGORITHM_IDENTIFIER`


    .. attribute:: HashEncryptionAlgorithm

        :class:`CRYPT_ALGORITHM_IDENTIFIER`


    .. attribute:: EncryptedHash

        :class:`CRYPT_DATA_BLOB`


    .. attribute:: AuthAttrs

        :class:`CRYPT_ATTRIBUTES`


    .. attribute:: UnauthAttrs

        :class:`CRYPT_ATTRIBUTES`

_SPC_SERIALIZED_OBJECT
''''''''''''''''''''''
.. class:: SPC_SERIALIZED_OBJECT

    Alias for :class:`_SPC_SERIALIZED_OBJECT`

.. class:: PSPC_SERIALIZED_OBJECT

    Pointer to :class:`_SPC_SERIALIZED_OBJECT`

.. class:: _SPC_SERIALIZED_OBJECT

    .. attribute:: ClassId

        :class:`SPC_UUID`


    .. attribute:: SerializedData

        :class:`CRYPT_DATA_BLOB`

_TMP_SPC_LINK_UNION
'''''''''''''''''''
.. class:: TMP_SPC_LINK_UNION

    Alias for :class:`_TMP_SPC_LINK_UNION`

.. class:: _TMP_SPC_LINK_UNION

    .. attribute:: pwszUrl

        :class:`LPWSTR`


    .. attribute:: Moniker

        :class:`SPC_SERIALIZED_OBJECT`


    .. attribute:: pwszFile

        :class:`LPWSTR`

SPC_LINK_
'''''''''
.. class:: PSPC_LINK

    Pointer to :class:`SPC_LINK_`

.. class:: SPC_LINK

    Alias for :class:`SPC_LINK_`

.. class:: SPC_LINK_

    .. attribute:: dwLinkChoice

        :class:`DWORD`


    .. attribute:: u

        :class:`TMP_SPC_LINK_UNION`

_SPC_SP_OPUS_INFO
'''''''''''''''''
.. class:: PSPC_SP_OPUS_INFO

    Pointer to :class:`_SPC_SP_OPUS_INFO`

.. class:: SPC_SP_OPUS_INFO

    Alias for :class:`_SPC_SP_OPUS_INFO`

.. class:: _SPC_SP_OPUS_INFO

    .. attribute:: pwszProgramName

        :class:`LPCWSTR`


    .. attribute:: pMoreInfo

        :class:`SPC_LINK_`


    .. attribute:: pPublisherInfo

        :class:`SPC_LINK_`

_CERT_TRUST_STATUS
''''''''''''''''''
.. class:: PCERT_TRUST_STATUS

    Pointer to :class:`_CERT_TRUST_STATUS`

.. class:: CERT_TRUST_STATUS

    Alias for :class:`_CERT_TRUST_STATUS`

.. class:: _CERT_TRUST_STATUS

    .. attribute:: dwErrorStatus

        :class:`DWORD`


    .. attribute:: dwInfoStatus

        :class:`DWORD`

_CERT_TRUST_LIST_INFO
'''''''''''''''''''''
.. class:: PCERT_TRUST_LIST_INFO

    Pointer to :class:`_CERT_TRUST_LIST_INFO`

.. class:: CERT_TRUST_LIST_INFO

    Alias for :class:`_CERT_TRUST_LIST_INFO`

.. class:: _CERT_TRUST_LIST_INFO

    .. attribute:: cbSize

        :class:`DWORD`


    .. attribute:: pCtlEntry

        :class:`PCTL_ENTRY`


    .. attribute:: pCtlContext

        :class:`PCCTL_CONTEXT`

_CERT_CONTEXT
'''''''''''''
.. class:: PCCERT_CONTEXT

    Pointer to :class:`_CERT_CONTEXT`

.. class:: CERT_CONTEXT

    Alias for :class:`_CERT_CONTEXT`

.. class:: PCERT_CONTEXT

    Pointer to :class:`_CERT_CONTEXT`

.. class:: _CERT_CONTEXT

    .. attribute:: dwCertEncodingType

        :class:`DWORD`


    .. attribute:: pbCertEncoded

        :class:`BYTE`


    .. attribute:: cbCertEncoded

        :class:`DWORD`


    .. attribute:: pCertInfo

        :class:`PCERT_INFO`


    .. attribute:: hCertStore

        :class:`HCERTSTORE`

_CRL_ENTRY
''''''''''
.. class:: CRL_ENTRY

    Alias for :class:`_CRL_ENTRY`

.. class:: PCRL_ENTRY

    Pointer to :class:`_CRL_ENTRY`

.. class:: _CRL_ENTRY

    .. attribute:: SerialNumber

        :class:`CRYPT_INTEGER_BLOB`


    .. attribute:: RevocationDate

        :class:`FILETIME`


    .. attribute:: cExtension

        :class:`DWORD`


    .. attribute:: rgExtension

        :class:`PCERT_EXTENSION`

_CRL_INFO
'''''''''
.. class:: CRL_INFO

    Alias for :class:`_CRL_INFO`

.. class:: PCRL_INFO

    Pointer to :class:`_CRL_INFO`

.. class:: _CRL_INFO

    .. attribute:: dwVersion

        :class:`DWORD`


    .. attribute:: SignatureAlgorithm

        :class:`CRYPT_ALGORITHM_IDENTIFIER`


    .. attribute:: Issuer

        :class:`CERT_NAME_BLOB`


    .. attribute:: ThisUpdate

        :class:`FILETIME`


    .. attribute:: NextUpdate

        :class:`FILETIME`


    .. attribute:: cCRLEntry

        :class:`DWORD`


    .. attribute:: rgCRLEntry

        :class:`PCRL_ENTRY`


    .. attribute:: cExtension

        :class:`DWORD`


    .. attribute:: rgExtension

        :class:`PCERT_EXTENSION`

_CRL_CONTEXT
''''''''''''
.. class:: PCCRL_CONTEXT

    Pointer to :class:`_CRL_CONTEXT`

.. class:: CRL_CONTEXT

    Alias for :class:`_CRL_CONTEXT`

.. class:: PCRL_CONTEXT

    Pointer to :class:`_CRL_CONTEXT`

.. class:: _CRL_CONTEXT

    .. attribute:: dwCertEncodingType

        :class:`DWORD`


    .. attribute:: pbCrlEncoded

        :class:`BYTE`


    .. attribute:: cbCrlEncoded

        :class:`DWORD`


    .. attribute:: pCrlInfo

        :class:`PCRL_INFO`


    .. attribute:: hCertStore

        :class:`HCERTSTORE`

_CERT_REVOCATION_CRL_INFO
'''''''''''''''''''''''''
.. class:: CERT_REVOCATION_CRL_INFO

    Alias for :class:`_CERT_REVOCATION_CRL_INFO`

.. class:: PCERT_REVOCATION_CRL_INFO

    Pointer to :class:`_CERT_REVOCATION_CRL_INFO`

.. class:: _CERT_REVOCATION_CRL_INFO

    .. attribute:: cbSize

        :class:`DWORD`


    .. attribute:: pBaseCrlContext

        :class:`PCCRL_CONTEXT`


    .. attribute:: pDeltaCrlContext

        :class:`PCCRL_CONTEXT`


    .. attribute:: pCrlEntry

        :class:`PCRL_ENTRY`


    .. attribute:: fDeltaCrlEntry

        :class:`BOOL`

_CERT_REVOCATION_INFO
'''''''''''''''''''''
.. class:: CERT_REVOCATION_INFO

    Alias for :class:`_CERT_REVOCATION_INFO`

.. class:: PCERT_REVOCATION_INFO

    Pointer to :class:`_CERT_REVOCATION_INFO`

.. class:: _CERT_REVOCATION_INFO

    .. attribute:: cbSize

        :class:`DWORD`


    .. attribute:: dwRevocationResult

        :class:`DWORD`


    .. attribute:: pszRevocationOid

        :class:`LPCSTR`


    .. attribute:: pvOidSpecificInfo

        :class:`LPVOID`


    .. attribute:: fHasFreshnessTime

        :class:`BOOL`


    .. attribute:: dwFreshnessTime

        :class:`DWORD`


    .. attribute:: pCrlInfo

        :class:`PCERT_REVOCATION_CRL_INFO`

_CERT_CHAIN_ELEMENT
'''''''''''''''''''
.. class:: PCERT_CHAIN_ELEMENT

    Pointer to :class:`_CERT_CHAIN_ELEMENT`

.. class:: CERT_CHAIN_ELEMENT

    Alias for :class:`_CERT_CHAIN_ELEMENT`

.. class:: PCCERT_CHAIN_ELEMENT

    Pointer to :class:`_CERT_CHAIN_ELEMENT`

.. class:: _CERT_CHAIN_ELEMENT

    .. attribute:: cbSize

        :class:`DWORD`


    .. attribute:: pCertContext

        :class:`PCCERT_CONTEXT`


    .. attribute:: TrustStatus

        :class:`CERT_TRUST_STATUS`


    .. attribute:: pRevocationInfo

        :class:`PCERT_REVOCATION_INFO`


    .. attribute:: pIssuanceUsage

        :class:`PCERT_ENHKEY_USAGE`


    .. attribute:: pApplicationUsage

        :class:`PCERT_ENHKEY_USAGE`


    .. attribute:: pwszExtendedErrorInfo

        :class:`LPCWSTR`

_CERT_SIMPLE_CHAIN
''''''''''''''''''
.. class:: CERT_SIMPLE_CHAIN

    Alias for :class:`_CERT_SIMPLE_CHAIN`

.. class:: PCERT_SIMPLE_CHAIN

    Pointer to :class:`_CERT_SIMPLE_CHAIN`

.. class:: PCCERT_SIMPLE_CHAIN

    Pointer to :class:`_CERT_SIMPLE_CHAIN`

.. class:: _CERT_SIMPLE_CHAIN

    .. attribute:: cbSize

        :class:`DWORD`


    .. attribute:: TrustStatus

        :class:`CERT_TRUST_STATUS`


    .. attribute:: cElement

        :class:`DWORD`


    .. attribute:: rgpElement

        :class:`PCERT_CHAIN_ELEMENT`


    .. attribute:: pTrustListInfo

        :class:`PCERT_TRUST_LIST_INFO`


    .. attribute:: fHasRevocationFreshnessTime

        :class:`BOOL`


    .. attribute:: dwRevocationFreshnessTime

        :class:`DWORD`

_CERT_CHAIN_CONTEXT
'''''''''''''''''''
.. class:: CERT_CHAIN_CONTEXT

    Alias for :class:`_CERT_CHAIN_CONTEXT`

.. class:: PCERT_CHAIN_CONTEXT

    Pointer to :class:`_CERT_CHAIN_CONTEXT`

.. class:: PCCERT_CHAIN_CONTEXT

    Pointer to :class:`_CERT_CHAIN_CONTEXT`

.. class:: _CERT_CHAIN_CONTEXT

    .. attribute:: cbSize

        :class:`DWORD`


    .. attribute:: TrustStatus

        :class:`CERT_TRUST_STATUS`


    .. attribute:: cChain

        :class:`DWORD`


    .. attribute:: rgpChain

        :class:`PCERT_SIMPLE_CHAIN`


    .. attribute:: cLowerQualityChainContext

        :class:`DWORD`


    .. attribute:: rgpLowerQualityChainContext

        :class:`PCCERT_CHAIN_CONTEXT`


    .. attribute:: fHasRevocationFreshnessTime

        :class:`BOOL`


    .. attribute:: dwRevocationFreshnessTime

        :class:`DWORD`


    .. attribute:: dwCreateFlags

        :class:`DWORD`


    .. attribute:: ChainId

        :class:`GUID`

_CERT_USAGE_MATCH
'''''''''''''''''
.. class:: CERT_USAGE_MATCH

    Alias for :class:`_CERT_USAGE_MATCH`

.. class:: PCERT_USAGE_MATCH

    Pointer to :class:`_CERT_USAGE_MATCH`

.. class:: _CERT_USAGE_MATCH

    .. attribute:: dwType

        :class:`DWORD`


    .. attribute:: Usage

        :class:`CERT_ENHKEY_USAGE`

_CERT_CHAIN_PARA
''''''''''''''''
.. class:: CERT_CHAIN_PARA

    Alias for :class:`_CERT_CHAIN_PARA`

.. class:: PCERT_CHAIN_PARA

    Pointer to :class:`_CERT_CHAIN_PARA`

.. class:: _CERT_CHAIN_PARA

    .. attribute:: cbSize

        :class:`DWORD`


    .. attribute:: RequestedUsage

        :class:`CERT_USAGE_MATCH`


    .. attribute:: RequestedIssuancePolicy

        :class:`CERT_USAGE_MATCH`


    .. attribute:: dwUrlRetrievalTimeout

        :class:`DWORD`


    .. attribute:: fCheckRevocationFreshnessTime

        :class:`BOOL`


    .. attribute:: dwRevocationFreshnessTime

        :class:`DWORD`


    .. attribute:: pftCacheResync

        :class:`LPFILETIME`

_CERT_CHAIN_ENGINE_CONFIG
'''''''''''''''''''''''''
.. class:: CERT_CHAIN_ENGINE_CONFIG

    Alias for :class:`_CERT_CHAIN_ENGINE_CONFIG`

.. class:: PCERT_CHAIN_ENGINE_CONFIG

    Pointer to :class:`_CERT_CHAIN_ENGINE_CONFIG`

.. class:: _CERT_CHAIN_ENGINE_CONFIG

    .. attribute:: cbSize

        :class:`DWORD`


    .. attribute:: hRestrictedRoot

        :class:`HCERTSTORE`


    .. attribute:: hRestrictedTrust

        :class:`HCERTSTORE`


    .. attribute:: hRestrictedOther

        :class:`HCERTSTORE`


    .. attribute:: cAdditionalStore

        :class:`DWORD`


    .. attribute:: rghAdditionalStore

        :class:`HCERTSTORE`


    .. attribute:: dwFlags

        :class:`DWORD`


    .. attribute:: dwUrlRetrievalTimeout

        :class:`DWORD`


    .. attribute:: MaximumCachedCertificates

        :class:`DWORD`


    .. attribute:: CycleDetectionModulus

        :class:`DWORD`

_SYSTEMTIME
'''''''''''
.. class:: LPSYSTEMTIME

    Pointer to :class:`_SYSTEMTIME`

.. class:: SYSTEMTIME

    Alias for :class:`_SYSTEMTIME`

.. class:: PSYSTEMTIME

    Pointer to :class:`_SYSTEMTIME`

.. class:: _SYSTEMTIME

    .. attribute:: wYear

        :class:`WORD`


    .. attribute:: wMonth

        :class:`WORD`


    .. attribute:: wDayOfWeek

        :class:`WORD`


    .. attribute:: wDay

        :class:`WORD`


    .. attribute:: wHour

        :class:`WORD`


    .. attribute:: wMinute

        :class:`WORD`


    .. attribute:: wSecond

        :class:`WORD`


    .. attribute:: wMilliseconds

        :class:`WORD`

_CERT_EXTENSIONS
''''''''''''''''
.. class:: PCERT_EXTENSIONS

    Pointer to :class:`_CERT_EXTENSIONS`

.. class:: CERT_EXTENSIONS

    Alias for :class:`_CERT_EXTENSIONS`

.. class:: _CERT_EXTENSIONS

    .. attribute:: cExtension

        :class:`DWORD`


    .. attribute:: rgExtension

        :class:`PCERT_EXTENSION`

_CRYPT_KEY_PROV_PARAM
'''''''''''''''''''''
.. class:: CRYPT_KEY_PROV_PARAM

    Alias for :class:`_CRYPT_KEY_PROV_PARAM`

.. class:: PCRYPT_KEY_PROV_PARAM

    Pointer to :class:`_CRYPT_KEY_PROV_PARAM`

.. class:: _CRYPT_KEY_PROV_PARAM

    .. attribute:: dwParam

        :class:`DWORD`


    .. attribute:: pbData

        :class:`BYTE`


    .. attribute:: cbData

        :class:`DWORD`


    .. attribute:: dwFlags

        :class:`DWORD`

_CRYPT_KEY_PROV_INFO
''''''''''''''''''''
.. class:: CRYPT_KEY_PROV_INFO

    Alias for :class:`_CRYPT_KEY_PROV_INFO`

.. class:: PCRYPT_KEY_PROV_INFO

    Pointer to :class:`_CRYPT_KEY_PROV_INFO`

.. class:: _CRYPT_KEY_PROV_INFO

    .. attribute:: pwszContainerName

        :class:`LPWSTR`


    .. attribute:: pwszProvName

        :class:`LPWSTR`


    .. attribute:: dwProvType

        :class:`DWORD`


    .. attribute:: dwFlags

        :class:`DWORD`


    .. attribute:: cProvParam

        :class:`DWORD`


    .. attribute:: rgProvParam

        :class:`PCRYPT_KEY_PROV_PARAM`


    .. attribute:: dwKeySpec

        :class:`DWORD`

_CRYPT_ENCRYPT_MESSAGE_PARA
'''''''''''''''''''''''''''
.. class:: PCRYPT_ENCRYPT_MESSAGE_PARA

    Pointer to :class:`_CRYPT_ENCRYPT_MESSAGE_PARA`

.. class:: CRYPT_ENCRYPT_MESSAGE_PARA

    Alias for :class:`_CRYPT_ENCRYPT_MESSAGE_PARA`

.. class:: _CRYPT_ENCRYPT_MESSAGE_PARA

    .. attribute:: cbSize

        :class:`DWORD`


    .. attribute:: dwMsgEncodingType

        :class:`DWORD`


    .. attribute:: hCryptProv

        :class:`HCRYPTPROV_LEGACY`


    .. attribute:: ContentEncryptionAlgorithm

        :class:`CRYPT_ALGORITHM_IDENTIFIER`


    .. attribute:: pvEncryptionAuxInfo

        :class:`VOID`


    .. attribute:: dwFlags

        :class:`DWORD`


    .. attribute:: dwInnerContentType

        :class:`DWORD`

_CRYPT_DECRYPT_MESSAGE_PARA
'''''''''''''''''''''''''''
.. class:: PCRYPT_DECRYPT_MESSAGE_PARA

    Pointer to :class:`_CRYPT_DECRYPT_MESSAGE_PARA`

.. class:: CRYPT_DECRYPT_MESSAGE_PARA

    Alias for :class:`_CRYPT_DECRYPT_MESSAGE_PARA`

.. class:: _CRYPT_DECRYPT_MESSAGE_PARA

    .. attribute:: cbSize

        :class:`DWORD`


    .. attribute:: dwMsgAndCertEncodingType

        :class:`DWORD`


    .. attribute:: cCertStore

        :class:`DWORD`


    .. attribute:: rghCertStore

        :class:`HCERTSTORE`


    .. attribute:: dwFlags

        :class:`DWORD`

_CERT_KEY_CONTEXT
'''''''''''''''''
.. class:: CERT_KEY_CONTEXT

    Alias for :class:`_CERT_KEY_CONTEXT`

.. class:: PCERT_KEY_CONTEXT

    Pointer to :class:`_CERT_KEY_CONTEXT`

.. class:: _CERT_KEY_CONTEXT

    .. attribute:: cbSize

        :class:`DWORD`


    .. attribute:: hCryptProv

        :class:`HCRYPTPROV`


    .. attribute:: dwKeySpec

        :class:`DWORD`

_CRYPT_ENCODE_PARA
''''''''''''''''''
.. class:: PCRYPT_ENCODE_PARA

    Pointer to :class:`_CRYPT_ENCODE_PARA`

.. class:: CRYPT_ENCODE_PARA

    Alias for :class:`_CRYPT_ENCODE_PARA`

.. class:: _CRYPT_ENCODE_PARA

    .. attribute:: cbSize

        :class:`DWORD`


    .. attribute:: pfnAlloc

        :class:`PVOID`


    .. attribute:: pfnFree

        :class:`PVOID`

_ACL
''''
.. class:: PACL

    Pointer to :class:`_ACL`

.. class:: ACL

    Alias for :class:`_ACL`

.. class:: _ACL

    .. attribute:: AclRevision

        :class:`BYTE`


    .. attribute:: Sbz1

        :class:`BYTE`


    .. attribute:: AclSize

        :class:`WORD`


    .. attribute:: AceCount

        :class:`WORD`


    .. attribute:: Sbz2

        :class:`WORD`

_ACE_HEADER
'''''''''''
.. class:: PACE_HEADER

    Pointer to :class:`_ACE_HEADER`

.. class:: ACE_HEADER

    Alias for :class:`_ACE_HEADER`

.. class:: _ACE_HEADER

    .. attribute:: AceType

        :class:`BYTE`


    .. attribute:: AceFlags

        :class:`BYTE`


    .. attribute:: AceSize

        :class:`WORD`

_ACCESS_ALLOWED_ACE
'''''''''''''''''''
.. class:: PACCESS_ALLOWED_ACE

    Pointer to :class:`_ACCESS_ALLOWED_ACE`

.. class:: ACCESS_ALLOWED_ACE

    Alias for :class:`_ACCESS_ALLOWED_ACE`

.. class:: _ACCESS_ALLOWED_ACE

    .. attribute:: Header

        :class:`ACE_HEADER`


    .. attribute:: Mask

        :class:`ACCESS_MASK`


    .. attribute:: SidStart

        :class:`DWORD`

_ACCESS_ALLOWED_CALLBACK_ACE
''''''''''''''''''''''''''''
.. class:: PACCESS_ALLOWED_CALLBACK_ACE

    Pointer to :class:`_ACCESS_ALLOWED_CALLBACK_ACE`

.. class:: ACCESS_ALLOWED_CALLBACK_ACE

    Alias for :class:`_ACCESS_ALLOWED_CALLBACK_ACE`

.. class:: _ACCESS_ALLOWED_CALLBACK_ACE

    .. attribute:: Header

        :class:`ACE_HEADER`


    .. attribute:: Mask

        :class:`ACCESS_MASK`


    .. attribute:: SidStart

        :class:`DWORD`

_ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
'''''''''''''''''''''''''''''''''''
.. class:: PACCESS_ALLOWED_CALLBACK_OBJECT_ACE

    Pointer to :class:`_ACCESS_ALLOWED_CALLBACK_OBJECT_ACE`

.. class:: ACCESS_ALLOWED_CALLBACK_OBJECT_ACE

    Alias for :class:`_ACCESS_ALLOWED_CALLBACK_OBJECT_ACE`

.. class:: _ACCESS_ALLOWED_CALLBACK_OBJECT_ACE

    .. attribute:: Header

        :class:`ACE_HEADER`


    .. attribute:: Mask

        :class:`ACCESS_MASK`


    .. attribute:: Flags

        :class:`DWORD`


    .. attribute:: ObjectType

        :class:`GUID`


    .. attribute:: InheritedObjectType

        :class:`GUID`


    .. attribute:: SidStart

        :class:`DWORD`

_ACCESS_ALLOWED_OBJECT_ACE
''''''''''''''''''''''''''
.. class:: PACCESS_ALLOWED_OBJECT_ACE

    Pointer to :class:`_ACCESS_ALLOWED_OBJECT_ACE`

.. class:: ACCESS_ALLOWED_OBJECT_ACE

    Alias for :class:`_ACCESS_ALLOWED_OBJECT_ACE`

.. class:: _ACCESS_ALLOWED_OBJECT_ACE

    .. attribute:: Header

        :class:`ACE_HEADER`


    .. attribute:: Mask

        :class:`ACCESS_MASK`


    .. attribute:: Flags

        :class:`DWORD`


    .. attribute:: ObjectType

        :class:`GUID`


    .. attribute:: InheritedObjectType

        :class:`GUID`


    .. attribute:: SidStart

        :class:`DWORD`

_ACCESS_DENIED_ACE
''''''''''''''''''
.. class:: ACCESS_DENIED_ACE

    Alias for :class:`_ACCESS_DENIED_ACE`

.. class:: PACCESS_DENIED_ACE

    Pointer to :class:`_ACCESS_DENIED_ACE`

.. class:: _ACCESS_DENIED_ACE

    .. attribute:: Header

        :class:`ACE_HEADER`


    .. attribute:: Mask

        :class:`ACCESS_MASK`


    .. attribute:: SidStart

        :class:`DWORD`

_ACCESS_DENIED_CALLBACK_ACE
'''''''''''''''''''''''''''
.. class:: ACCESS_DENIED_CALLBACK_ACE

    Alias for :class:`_ACCESS_DENIED_CALLBACK_ACE`

.. class:: PACCESS_DENIED_CALLBACK_ACE

    Pointer to :class:`_ACCESS_DENIED_CALLBACK_ACE`

.. class:: _ACCESS_DENIED_CALLBACK_ACE

    .. attribute:: Header

        :class:`ACE_HEADER`


    .. attribute:: Mask

        :class:`ACCESS_MASK`


    .. attribute:: SidStart

        :class:`DWORD`

_ACCESS_DENIED_OBJECT_ACE
'''''''''''''''''''''''''
.. class:: ACCESS_DENIED_OBJECT_ACE

    Alias for :class:`_ACCESS_DENIED_OBJECT_ACE`

.. class:: PACCESS_DENIED_OBJECT_ACE

    Pointer to :class:`_ACCESS_DENIED_OBJECT_ACE`

.. class:: _ACCESS_DENIED_OBJECT_ACE

    .. attribute:: Header

        :class:`ACE_HEADER`


    .. attribute:: Mask

        :class:`ACCESS_MASK`


    .. attribute:: Flags

        :class:`DWORD`


    .. attribute:: ObjectType

        :class:`GUID`


    .. attribute:: InheritedObjectType

        :class:`GUID`


    .. attribute:: SidStart

        :class:`DWORD`

_SYSTEM_MANDATORY_LABEL_ACE
'''''''''''''''''''''''''''
.. class:: SYSTEM_MANDATORY_LABEL_ACE

    Alias for :class:`_SYSTEM_MANDATORY_LABEL_ACE`

.. class:: PSYSTEM_MANDATORY_LABEL_ACE

    Pointer to :class:`_SYSTEM_MANDATORY_LABEL_ACE`

.. class:: _SYSTEM_MANDATORY_LABEL_ACE

    .. attribute:: Header

        :class:`ACE_HEADER`


    .. attribute:: Mask

        :class:`ACCESS_MASK`


    .. attribute:: SidStart

        :class:`DWORD`

_RTL_UNLOAD_EVENT_TRACE
'''''''''''''''''''''''
.. class:: PRTL_UNLOAD_EVENT_TRACE

    Pointer to :class:`_RTL_UNLOAD_EVENT_TRACE`

.. class:: RTL_UNLOAD_EVENT_TRACE

    Alias for :class:`_RTL_UNLOAD_EVENT_TRACE`

.. class:: _RTL_UNLOAD_EVENT_TRACE

    .. attribute:: BaseAddress

        :class:`PVOID`


    .. attribute:: SizeOfImage

        :class:`SIZE_T`


    .. attribute:: Sequence

        :class:`ULONG`


    .. attribute:: TimeDateStamp

        :class:`ULONG`


    .. attribute:: CheckSum

        :class:`ULONG`


    .. attribute:: ImageName

        :class:`WCHAR` ``[32]``


    .. attribute:: Version

        :class:`ULONG` ``[2]``

_RTL_UNLOAD_EVENT_TRACE32
'''''''''''''''''''''''''
.. class:: RTL_UNLOAD_EVENT_TRACE32

    Alias for :class:`_RTL_UNLOAD_EVENT_TRACE32`

.. class:: PRTL_UNLOAD_EVENT_TRACE32

    Pointer to :class:`_RTL_UNLOAD_EVENT_TRACE32`

.. class:: _RTL_UNLOAD_EVENT_TRACE32

    .. attribute:: BaseAddress

        :class:`DWORD`


    .. attribute:: SizeOfImage

        :class:`DWORD`


    .. attribute:: Sequence

        :class:`ULONG`


    .. attribute:: TimeDateStamp

        :class:`ULONG`


    .. attribute:: CheckSum

        :class:`ULONG`


    .. attribute:: ImageName

        :class:`WCHAR` ``[32]``


    .. attribute:: Version

        :class:`ULONG` ``[2]``

_RTL_UNLOAD_EVENT_TRACE64
'''''''''''''''''''''''''
.. class:: PRTL_UNLOAD_EVENT_TRACE64

    Pointer to :class:`_RTL_UNLOAD_EVENT_TRACE64`

.. class:: RTL_UNLOAD_EVENT_TRACE64

    Alias for :class:`_RTL_UNLOAD_EVENT_TRACE64`

.. class:: _RTL_UNLOAD_EVENT_TRACE64

    .. attribute:: BaseAddress

        :class:`ULONGLONG`


    .. attribute:: SizeOfImage

        :class:`ULONGLONG`


    .. attribute:: Sequence

        :class:`ULONG`


    .. attribute:: TimeDateStamp

        :class:`ULONG`


    .. attribute:: CheckSum

        :class:`ULONG`


    .. attribute:: ImageName

        :class:`WCHAR` ``[32]``


    .. attribute:: Version

        :class:`ULONG` ``[2]``

_FILE_FS_ATTRIBUTE_INFORMATION
''''''''''''''''''''''''''''''
.. class:: PFILE_FS_ATTRIBUTE_INFORMATION

    Pointer to :class:`_FILE_FS_ATTRIBUTE_INFORMATION`

.. class:: FILE_FS_ATTRIBUTE_INFORMATION

    Alias for :class:`_FILE_FS_ATTRIBUTE_INFORMATION`

.. class:: _FILE_FS_ATTRIBUTE_INFORMATION

    .. attribute:: FileSystemAttributes

        :class:`ULONG`


    .. attribute:: MaximumComponentNameLength

        :class:`LONG`


    .. attribute:: FileSystemNameLength

        :class:`ULONG`


    .. attribute:: FileSystemName

        :class:`WCHAR` ``[1]``

_FILE_FS_LABEL_INFORMATION
''''''''''''''''''''''''''
.. class:: FILE_FS_LABEL_INFORMATION

    Alias for :class:`_FILE_FS_LABEL_INFORMATION`

.. class:: PFILE_FS_LABEL_INFORMATION

    Pointer to :class:`_FILE_FS_LABEL_INFORMATION`

.. class:: _FILE_FS_LABEL_INFORMATION

    .. attribute:: VolumeLabelLength

        :class:`ULONG`


    .. attribute:: VolumeLabel

        :class:`WCHAR` ``[1]``

_FILE_FS_SIZE_INFORMATION
'''''''''''''''''''''''''
.. class:: PFILE_FS_SIZE_INFORMATION

    Pointer to :class:`_FILE_FS_SIZE_INFORMATION`

.. class:: FILE_FS_SIZE_INFORMATION

    Alias for :class:`_FILE_FS_SIZE_INFORMATION`

.. class:: _FILE_FS_SIZE_INFORMATION

    .. attribute:: TotalAllocationUnits

        :class:`LARGE_INTEGER`


    .. attribute:: AvailableAllocationUnits

        :class:`LARGE_INTEGER`


    .. attribute:: SectorsPerAllocationUnit

        :class:`ULONG`


    .. attribute:: BytesPerSector

        :class:`ULONG`

_FILE_FS_DEVICE_INFORMATION
'''''''''''''''''''''''''''
.. class:: FILE_FS_DEVICE_INFORMATION

    Alias for :class:`_FILE_FS_DEVICE_INFORMATION`

.. class:: PFILE_FS_DEVICE_INFORMATION

    Pointer to :class:`_FILE_FS_DEVICE_INFORMATION`

.. class:: _FILE_FS_DEVICE_INFORMATION

    .. attribute:: DeviceType

        :class:`DEVICE_TYPE`


    .. attribute:: Characteristics

        :class:`ULONG`

_FILE_FS_CONTROL_INFORMATION
''''''''''''''''''''''''''''
.. class:: FILE_FS_CONTROL_INFORMATION

    Alias for :class:`_FILE_FS_CONTROL_INFORMATION`

.. class:: PFILE_FS_CONTROL_INFORMATION

    Pointer to :class:`_FILE_FS_CONTROL_INFORMATION`

.. class:: _FILE_FS_CONTROL_INFORMATION

    .. attribute:: FreeSpaceStartFiltering

        :class:`LARGE_INTEGER`


    .. attribute:: FreeSpaceThreshold

        :class:`LARGE_INTEGER`


    .. attribute:: FreeSpaceStopFiltering

        :class:`LARGE_INTEGER`


    .. attribute:: DefaultQuotaThreshold

        :class:`LARGE_INTEGER`


    .. attribute:: DefaultQuotaLimit

        :class:`LARGE_INTEGER`


    .. attribute:: FileSystemControlFlags

        :class:`ULONG`

_FILE_FS_FULL_SIZE_INFORMATION
''''''''''''''''''''''''''''''
.. class:: PFILE_FS_FULL_SIZE_INFORMATION

    Pointer to :class:`_FILE_FS_FULL_SIZE_INFORMATION`

.. class:: FILE_FS_FULL_SIZE_INFORMATION

    Alias for :class:`_FILE_FS_FULL_SIZE_INFORMATION`

.. class:: _FILE_FS_FULL_SIZE_INFORMATION

    .. attribute:: TotalAllocationUnits

        :class:`LARGE_INTEGER`


    .. attribute:: CallerAvailableAllocationUnits

        :class:`LARGE_INTEGER`


    .. attribute:: ActualAvailableAllocationUnits

        :class:`LARGE_INTEGER`


    .. attribute:: SectorsPerAllocationUnit

        :class:`ULONG`


    .. attribute:: BytesPerSector

        :class:`ULONG`

_FILE_FS_OBJECTID_INFORMATION
'''''''''''''''''''''''''''''
.. class:: FILE_FS_OBJECTID_INFORMATION

    Alias for :class:`_FILE_FS_OBJECTID_INFORMATION`

.. class:: PFILE_FS_OBJECTID_INFORMATION

    Pointer to :class:`_FILE_FS_OBJECTID_INFORMATION`

.. class:: _FILE_FS_OBJECTID_INFORMATION

    .. attribute:: ObjectId

        :class:`UCHAR` ``[16]``


    .. attribute:: ExtendedInfo

        :class:`UCHAR` ``[48]``

_FILE_FS_DRIVER_PATH_INFORMATION
''''''''''''''''''''''''''''''''
.. class:: FILE_FS_DRIVER_PATH_INFORMATION

    Alias for :class:`_FILE_FS_DRIVER_PATH_INFORMATION`

.. class:: PFILE_FS_DRIVER_PATH_INFORMATION

    Pointer to :class:`_FILE_FS_DRIVER_PATH_INFORMATION`

.. class:: _FILE_FS_DRIVER_PATH_INFORMATION

    .. attribute:: DriverInPath

        :class:`BOOLEAN`


    .. attribute:: DriverNameLength

        :class:`ULONG`


    .. attribute:: DriverName

        :class:`WCHAR` ``[1]``

_FILE_FS_DRIVER_PATH_INFORMATION
''''''''''''''''''''''''''''''''
.. class:: FILE_FS_DRIVER_PATH_INFORMATION

    Alias for :class:`_FILE_FS_DRIVER_PATH_INFORMATION`

.. class:: PFILE_FS_DRIVER_PATH_INFORMATION

    Pointer to :class:`_FILE_FS_DRIVER_PATH_INFORMATION`

.. class:: _FILE_FS_DRIVER_PATH_INFORMATION

    .. attribute:: DriverInPath

        :class:`BOOLEAN`


    .. attribute:: DriverNameLength

        :class:`ULONG`


    .. attribute:: DriverName

        :class:`WCHAR` ``[1]``

_FILE_FS_VOLUME_INFORMATION
'''''''''''''''''''''''''''
.. class:: FILE_FS_VOLUME_INFORMATION

    Alias for :class:`_FILE_FS_VOLUME_INFORMATION`

.. class:: PFILE_FS_VOLUME_INFORMATION

    Pointer to :class:`_FILE_FS_VOLUME_INFORMATION`

.. class:: _FILE_FS_VOLUME_INFORMATION

    .. attribute:: VolumeCreationTime

        :class:`LARGE_INTEGER`


    .. attribute:: VolumeSerialNumber

        :class:`ULONG`


    .. attribute:: VolumeLabelLength

        :class:`ULONG`


    .. attribute:: SupportsObjects

        :class:`BOOLEAN`


    .. attribute:: VolumeLabel

        :class:`WCHAR` ``[1]``

_FILE_FS_SECTOR_SIZE_INFORMATION
''''''''''''''''''''''''''''''''
.. class:: PFILE_FS_SECTOR_SIZE_INFORMATION

    Pointer to :class:`_FILE_FS_SECTOR_SIZE_INFORMATION`

.. class:: FILE_FS_SECTOR_SIZE_INFORMATION

    Alias for :class:`_FILE_FS_SECTOR_SIZE_INFORMATION`

.. class:: _FILE_FS_SECTOR_SIZE_INFORMATION

    .. attribute:: LogicalBytesPerSector

        :class:`ULONG`


    .. attribute:: PhysicalBytesPerSectorForAtomicity

        :class:`ULONG`


    .. attribute:: PhysicalBytesPerSectorForPerformance

        :class:`ULONG`


    .. attribute:: FileSystemEffectivePhysicalBytesPerSectorForAtomicity

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: ByteOffsetForSectorAlignment

        :class:`ULONG`


    .. attribute:: ByteOffsetForPartitionAlignment

        :class:`ULONG`

_RTLP_CURDIR_REF
''''''''''''''''
.. class:: PRTLP_CURDIR_REF

    Pointer to :class:`_RTLP_CURDIR_REF`

.. class:: RTLP_CURDIR_REF

    Alias for :class:`_RTLP_CURDIR_REF`

.. class:: _RTLP_CURDIR_REF

    .. attribute:: RefCount

        :class:`LONG`


    .. attribute:: Handle

        :class:`HANDLE`

_RTL_RELATIVE_NAME_U
''''''''''''''''''''
.. class:: PRTL_RELATIVE_NAME_U

    Pointer to :class:`_RTL_RELATIVE_NAME_U`

.. class:: RTL_RELATIVE_NAME_U

    Alias for :class:`_RTL_RELATIVE_NAME_U`

.. class:: _RTL_RELATIVE_NAME_U

    .. attribute:: RelativeName

        :class:`UNICODE_STRING`


    .. attribute:: ContainingDirectory

        :class:`HANDLE`


    .. attribute:: CurDirRef

        :class:`PRTLP_CURDIR_REF`

_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
'''''''''''''''''''''''''''''''''''''''''''''
.. class:: PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION

    Pointer to :class:`_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION`

.. class:: PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION

    Alias for :class:`_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION`

.. class:: _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION

    .. attribute:: Version

        :class:`ULONG`


    .. attribute:: Reserved

        :class:`ULONG`


    .. attribute:: Callback

        :class:`PVOID`

_ALPC_PORT_ATTRIBUTES32
'''''''''''''''''''''''
.. class:: PALPC_PORT_ATTRIBUTES32

    Pointer to :class:`_ALPC_PORT_ATTRIBUTES32`

.. class:: ALPC_PORT_ATTRIBUTES32

    Alias for :class:`_ALPC_PORT_ATTRIBUTES32`

.. class:: _ALPC_PORT_ATTRIBUTES32

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: SecurityQos

        :class:`SECURITY_QUALITY_OF_SERVICE`


    .. attribute:: MaxMessageLength

        :class:`SIZE_T`


    .. attribute:: MemoryBandwidth

        :class:`SIZE_T`


    .. attribute:: MaxPoolUsage

        :class:`SIZE_T`


    .. attribute:: MaxSectionSize

        :class:`SIZE_T`


    .. attribute:: MaxViewSize

        :class:`SIZE_T`


    .. attribute:: MaxTotalSectionSize

        :class:`SIZE_T`


    .. attribute:: DupObjectTypes

        :class:`ULONG`

_ALPC_PORT_ATTRIBUTES64
'''''''''''''''''''''''
.. class:: ALPC_PORT_ATTRIBUTES64

    Alias for :class:`_ALPC_PORT_ATTRIBUTES64`

.. class:: PALPC_PORT_ATTRIBUTES64

    Pointer to :class:`_ALPC_PORT_ATTRIBUTES64`

.. class:: _ALPC_PORT_ATTRIBUTES64

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: SecurityQos

        :class:`SECURITY_QUALITY_OF_SERVICE`


    .. attribute:: MaxMessageLength

        :class:`SIZE_T`


    .. attribute:: MemoryBandwidth

        :class:`SIZE_T`


    .. attribute:: MaxPoolUsage

        :class:`SIZE_T`


    .. attribute:: MaxSectionSize

        :class:`SIZE_T`


    .. attribute:: MaxViewSize

        :class:`SIZE_T`


    .. attribute:: MaxTotalSectionSize

        :class:`SIZE_T`


    .. attribute:: DupObjectTypes

        :class:`ULONG`


    .. attribute:: Reserved

        :class:`ULONG`

_ALPC_MESSAGE_ATTRIBUTES
''''''''''''''''''''''''
.. class:: ALPC_MESSAGE_ATTRIBUTES

    Alias for :class:`_ALPC_MESSAGE_ATTRIBUTES`

.. class:: PALPC_MESSAGE_ATTRIBUTES

    Pointer to :class:`_ALPC_MESSAGE_ATTRIBUTES`

.. class:: _ALPC_MESSAGE_ATTRIBUTES

    .. attribute:: AllocatedAttributes

        :class:`ULONG`


    .. attribute:: ValidAttributes

        :class:`ULONG`

_PORT_MESSAGE32_TMP_UNION
'''''''''''''''''''''''''
.. class:: PORT_MESSAGE_TMP_UNION

    Alias for :class:`_PORT_MESSAGE32_TMP_UNION`

.. class:: _PORT_MESSAGE32_TMP_UNION

    .. attribute:: ClientViewSize

        :class:`ULONG`


    .. attribute:: CallbackId

        :class:`ULONG`

_PORT_MESSAGE64_TMP_UNION
'''''''''''''''''''''''''
.. class:: PORT_MESSAGE_TMP_UNION

    Alias for :class:`_PORT_MESSAGE64_TMP_UNION`

.. class:: _PORT_MESSAGE64_TMP_UNION

    .. attribute:: ClientViewSize

        :class:`ULONGLONG`


    .. attribute:: CallbackId

        :class:`ULONG`

_PORT_MESSAGE_TMP_SUBSTRUCT_S1
''''''''''''''''''''''''''''''
.. class:: _PORT_MESSAGE_TMP_SUBSTRUCT_S1

    Alias for :class:`_PORT_MESSAGE_TMP_SUBSTRUCT_S1`

.. class:: _PORT_MESSAGE_TMP_SUBSTRUCT_S1

    .. attribute:: DataLength

        :class:`CSHORT`


    .. attribute:: TotalLength

        :class:`CSHORT`

_PORT_MESSAGE_TMP_UNION_U1
''''''''''''''''''''''''''
.. class:: _PORT_MESSAGE_TMP_UNION_U1

    Alias for :class:`_PORT_MESSAGE_TMP_UNION_U1`

.. class:: _PORT_MESSAGE_TMP_UNION_U1

    .. attribute:: Length

        :class:`ULONG`


    .. attribute:: s1

        :class:`_PORT_MESSAGE_TMP_SUBSTRUCT_S1`

_PORT_MESSAGE_TMP_SUBSTRUCT_S2
''''''''''''''''''''''''''''''
.. class:: _PORT_MESSAGE_TMP_SUBSTRUCT_S2

    Alias for :class:`_PORT_MESSAGE_TMP_SUBSTRUCT_S2`

.. class:: _PORT_MESSAGE_TMP_SUBSTRUCT_S2

    .. attribute:: Type

        :class:`CSHORT`


    .. attribute:: DataInfoOffset

        :class:`CSHORT`

_PORT_MESSAGE_TMP_UNION_U2
''''''''''''''''''''''''''
.. class:: _PORT_MESSAGE_TMP_UNION_U2

    Alias for :class:`_PORT_MESSAGE_TMP_UNION_U2`

.. class:: _PORT_MESSAGE_TMP_UNION_U2

    .. attribute:: ZeroInit

        :class:`ULONG`


    .. attribute:: s2

        :class:`_PORT_MESSAGE_TMP_SUBSTRUCT_S2`

_PORT_MESSAGE32
'''''''''''''''
.. class:: PORT_MESSAGE32

    Alias for :class:`_PORT_MESSAGE32`

.. class:: PPORT_MESSAGE32

    Pointer to :class:`_PORT_MESSAGE32`

.. class:: _PORT_MESSAGE32

    .. attribute:: u1

        :class:`_PORT_MESSAGE_TMP_UNION_U1`


    .. attribute:: u2

        :class:`_PORT_MESSAGE_TMP_UNION_U2`


    .. attribute:: ClientId

        :class:`CLIENT_ID32`


    .. attribute:: MessageId

        :class:`ULONG`


    .. attribute:: tmp_union

        :class:`_PORT_MESSAGE32_TMP_UNION`

_PORT_MESSAGE64
'''''''''''''''
.. class:: PPORT_MESSAGE64

    Pointer to :class:`_PORT_MESSAGE64`

.. class:: PORT_MESSAGE64

    Alias for :class:`_PORT_MESSAGE64`

.. class:: _PORT_MESSAGE64

    .. attribute:: u1

        :class:`_PORT_MESSAGE_TMP_UNION_U1`


    .. attribute:: u2

        :class:`_PORT_MESSAGE_TMP_UNION_U2`


    .. attribute:: ClientId

        :class:`CLIENT_ID64`


    .. attribute:: MessageId

        :class:`ULONG`


    .. attribute:: tmp_union

        :class:`_PORT_MESSAGE64_TMP_UNION`

_ALPC_SERVER_INFORMATION_TMP_IN
'''''''''''''''''''''''''''''''
.. class:: ALPC_SERVER_INFORMATION_TMP_IN

    Alias for :class:`_ALPC_SERVER_INFORMATION_TMP_IN`

.. class:: _ALPC_SERVER_INFORMATION_TMP_IN

    .. attribute:: ThreadHandle

        :class:`HANDLE`

_ALPC_SERVER_INFORMATION_TMP_OUT
''''''''''''''''''''''''''''''''
.. class:: ALPC_SERVER_INFORMATION_TMP_OUT

    Alias for :class:`_ALPC_SERVER_INFORMATION_TMP_OUT`

.. class:: _ALPC_SERVER_INFORMATION_TMP_OUT

    .. attribute:: ThreadBlocked

        :class:`BOOLEAN`


    .. attribute:: ConnectedProcessId

        :class:`HANDLE`


    .. attribute:: ConnectionPortName

        :class:`UNICODE_STRING`

ALPC_SERVER_INFORMATION
'''''''''''''''''''''''
.. class:: ALPC_SERVER_INFORMATION

    Alias for :class:`ALPC_SERVER_INFORMATION`

.. class:: ALPC_SERVER_INFORMATION

    .. attribute:: In

        :class:`ALPC_SERVER_INFORMATION_TMP_IN`


    .. attribute:: Out

        :class:`ALPC_SERVER_INFORMATION_TMP_OUT`

_ALPC_CONTEXT_ATTR
''''''''''''''''''
.. class:: PALPC_CONTEXT_ATTR

    Pointer to :class:`_ALPC_CONTEXT_ATTR`

.. class:: ALPC_CONTEXT_ATTR

    Alias for :class:`_ALPC_CONTEXT_ATTR`

.. class:: _ALPC_CONTEXT_ATTR

    .. attribute:: PortContext

        :class:`PVOID`


    .. attribute:: MessageContext

        :class:`PVOID`


    .. attribute:: Sequence

        :class:`ULONG`


    .. attribute:: MessageId

        :class:`ULONG`


    .. attribute:: CallbackId

        :class:`ULONG`

_ALPC_CONTEXT_ATTR32
''''''''''''''''''''
.. class:: ALPC_CONTEXT_ATTR32

    Alias for :class:`_ALPC_CONTEXT_ATTR32`

.. class:: PALPC_CONTEXT_ATTR32

    Pointer to :class:`_ALPC_CONTEXT_ATTR32`

.. class:: _ALPC_CONTEXT_ATTR32

    .. attribute:: PortContext

        :class:`ULONG`


    .. attribute:: MessageContext

        :class:`ULONG`


    .. attribute:: Sequence

        :class:`ULONG`


    .. attribute:: MessageId

        :class:`ULONG`


    .. attribute:: CallbackId

        :class:`ULONG`

_ALPC_CONTEXT_ATTR64
''''''''''''''''''''
.. class:: ALPC_CONTEXT_ATTR64

    Alias for :class:`_ALPC_CONTEXT_ATTR64`

.. class:: PALPC_CONTEXT_ATTR64

    Pointer to :class:`_ALPC_CONTEXT_ATTR64`

.. class:: _ALPC_CONTEXT_ATTR64

    .. attribute:: PortContext

        :class:`ULONGLONG`


    .. attribute:: MessageContext

        :class:`ULONGLONG`


    .. attribute:: Sequence

        :class:`ULONG`


    .. attribute:: MessageId

        :class:`ULONG`


    .. attribute:: CallbackId

        :class:`ULONG`

_ALPC_HANDLE_ATTR
'''''''''''''''''
.. class:: PALPC_HANDLE_ATTR

    Pointer to :class:`_ALPC_HANDLE_ATTR`

.. class:: ALPC_HANDLE_ATTR

    Alias for :class:`_ALPC_HANDLE_ATTR`

.. class:: _ALPC_HANDLE_ATTR

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: Handle

        :class:`HANDLE`


    .. attribute:: ObjectType

        :class:`ULONG`


    .. attribute:: DesiredAccess

        :class:`ACCESS_MASK`

_ALPC_HANDLE_ATTR32
'''''''''''''''''''
.. class:: ALPC_HANDLE_ATTR32

    Alias for :class:`_ALPC_HANDLE_ATTR32`

.. class:: PALPC_HANDLE_ATTR32

    Pointer to :class:`_ALPC_HANDLE_ATTR32`

.. class:: _ALPC_HANDLE_ATTR32

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: Handle

        :class:`ULONG`


    .. attribute:: ObjectType

        :class:`ULONG`


    .. attribute:: DesiredAccess

        :class:`ACCESS_MASK`

_ALPC_HANDLE_ATTR64
'''''''''''''''''''
.. class:: PALPC_HANDLE_ATTR64

    Pointer to :class:`_ALPC_HANDLE_ATTR64`

.. class:: ALPC_HANDLE_ATTR64

    Alias for :class:`_ALPC_HANDLE_ATTR64`

.. class:: _ALPC_HANDLE_ATTR64

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: Handle

        :class:`ULONGLONG`


    .. attribute:: ObjectType

        :class:`ULONG`


    .. attribute:: DesiredAccess

        :class:`ACCESS_MASK`

_ALPC_SECURITY_ATTR
'''''''''''''''''''
.. class:: PALPC_SECURITY_ATTR

    Pointer to :class:`_ALPC_SECURITY_ATTR`

.. class:: ALPC_SECURITY_ATTR

    Alias for :class:`_ALPC_SECURITY_ATTR`

.. class:: _ALPC_SECURITY_ATTR

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: QoS

        :class:`PSECURITY_QUALITY_OF_SERVICE`


    .. attribute:: ContextHandle

        :class:`ALPC_HANDLE`

_ALPC_SECURITY_ATTR32
'''''''''''''''''''''
.. class:: ALPC_SECURITY_ATTR32

    Alias for :class:`_ALPC_SECURITY_ATTR32`

.. class:: PALPC_SECURITY_ATTR32

    Pointer to :class:`_ALPC_SECURITY_ATTR32`

.. class:: _ALPC_SECURITY_ATTR32

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: QoS

        :class:`ULONG`


    .. attribute:: ContextHandle

        :class:`ULONG`

_ALPC_SECURITY_ATTR64
'''''''''''''''''''''
.. class:: PALPC_SECURITY_ATTR64

    Pointer to :class:`_ALPC_SECURITY_ATTR64`

.. class:: ALPC_SECURITY_ATTR64

    Alias for :class:`_ALPC_SECURITY_ATTR64`

.. class:: _ALPC_SECURITY_ATTR64

    .. attribute:: Flags

        :class:`ULONGLONG`


    .. attribute:: QoS

        :class:`ULONGLONG`


    .. attribute:: ContextHandle

        :class:`ULONGLONG`

_ALPC_DATA_VIEW_ATTR
''''''''''''''''''''
.. class:: PALPC_DATA_VIEW_ATTR

    Pointer to :class:`_ALPC_DATA_VIEW_ATTR`

.. class:: ALPC_DATA_VIEW_ATTR

    Alias for :class:`_ALPC_DATA_VIEW_ATTR`

.. class:: _ALPC_DATA_VIEW_ATTR

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: SectionHandle

        :class:`ALPC_HANDLE`


    .. attribute:: ViewBase

        :class:`PVOID`


    .. attribute:: ViewSize

        :class:`PVOID`

_ALPC_DATA_VIEW_ATTR32
''''''''''''''''''''''
.. class:: PALPC_DATA_VIEW_ATTR32

    Pointer to :class:`_ALPC_DATA_VIEW_ATTR32`

.. class:: ALPC_DATA_VIEW_ATTR32

    Alias for :class:`_ALPC_DATA_VIEW_ATTR32`

.. class:: _ALPC_DATA_VIEW_ATTR32

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: SectionHandle

        :class:`ULONG`


    .. attribute:: ViewBase

        :class:`ULONG`


    .. attribute:: ViewSize

        :class:`ULONG`

_ALPC_DATA_VIEW_ATTR64
''''''''''''''''''''''
.. class:: PALPC_DATA_VIEW_ATTR64

    Pointer to :class:`_ALPC_DATA_VIEW_ATTR64`

.. class:: ALPC_DATA_VIEW_ATTR64

    Alias for :class:`_ALPC_DATA_VIEW_ATTR64`

.. class:: _ALPC_DATA_VIEW_ATTR64

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: SectionHandle

        :class:`ULONGLONG`


    .. attribute:: ViewBase

        :class:`ULONGLONG`


    .. attribute:: ViewSize

        :class:`ULONGLONG`

_ALPC_TOKEN_ATTR
''''''''''''''''
.. class:: ALPC_TOKEN_ATTR

    Alias for :class:`_ALPC_TOKEN_ATTR`

.. class:: PALPC_TOKEN_ATTR

    Pointer to :class:`_ALPC_TOKEN_ATTR`

.. class:: _ALPC_TOKEN_ATTR

    .. attribute:: TokenId

        :class:`ULONGLONG`


    .. attribute:: AuthenticationId

        :class:`ULONGLONG`


    .. attribute:: ModifiedId

        :class:`ULONGLONG`

_ALPC_DIRECT_ATTR
'''''''''''''''''
.. class:: ALPC_DIRECT_ATTR

    Alias for :class:`_ALPC_DIRECT_ATTR`

.. class:: PALPC_DIRECT_ATTR

    Pointer to :class:`_ALPC_DIRECT_ATTR`

.. class:: _ALPC_DIRECT_ATTR

    .. attribute:: Event

        :class:`HANDLE`

_ALPC_DIRECT_ATTR32
'''''''''''''''''''
.. class:: PALPC_DIRECT_ATTR32

    Pointer to :class:`_ALPC_DIRECT_ATTR32`

.. class:: ALPC_DIRECT_ATTR32

    Alias for :class:`_ALPC_DIRECT_ATTR32`

.. class:: _ALPC_DIRECT_ATTR32

    .. attribute:: Event

        :class:`ULONG`

_ALPC_DIRECT_ATTR64
'''''''''''''''''''
.. class:: ALPC_DIRECT_ATTR64

    Alias for :class:`_ALPC_DIRECT_ATTR64`

.. class:: PALPC_DIRECT_ATTR64

    Pointer to :class:`_ALPC_DIRECT_ATTR64`

.. class:: _ALPC_DIRECT_ATTR64

    .. attribute:: Event

        :class:`ULONGLONG`

_ALPC_WORK_ON_BEHALF_ATTR
'''''''''''''''''''''''''
.. class:: PALPC_WORK_ON_BEHALF_ATTR

    Pointer to :class:`_ALPC_WORK_ON_BEHALF_ATTR`

.. class:: ALPC_WORK_ON_BEHALF_ATTR

    Alias for :class:`_ALPC_WORK_ON_BEHALF_ATTR`

.. class:: _ALPC_WORK_ON_BEHALF_ATTR

    .. attribute:: Ticket

        :class:`ULONGLONG`

_RPC_IF_ID
''''''''''
.. class:: RPC_IF_ID

    Alias for :class:`_RPC_IF_ID`

.. class:: _RPC_IF_ID

    .. attribute:: Uuid

        :class:`IID`


    .. attribute:: VersMajor

        :class:`USHORT`


    .. attribute:: VersMinor

        :class:`USHORT`

_API_SET_VALUE_ENTRY
''''''''''''''''''''
.. class:: API_SET_VALUE_ENTRY

    Alias for :class:`_API_SET_VALUE_ENTRY`

.. class:: PAPI_SET_VALUE_ENTRY

    Pointer to :class:`_API_SET_VALUE_ENTRY`

.. class:: _API_SET_VALUE_ENTRY

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: NameOffset

        :class:`ULONG`


    .. attribute:: NameLength

        :class:`ULONG`


    .. attribute:: ValueOffset

        :class:`ULONG`


    .. attribute:: ValueLength

        :class:`ULONG`

_API_SET_NAMESPACE_ENTRY
''''''''''''''''''''''''
.. class:: PAPI_SET_NAMESPACE_ENTRY

    Pointer to :class:`_API_SET_NAMESPACE_ENTRY`

.. class:: API_SET_NAMESPACE_ENTRY

    Alias for :class:`_API_SET_NAMESPACE_ENTRY`

.. class:: _API_SET_NAMESPACE_ENTRY

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: NameOffset

        :class:`ULONG`


    .. attribute:: NameLength

        :class:`ULONG`


    .. attribute:: AliasOffset

        :class:`ULONG`


    .. attribute:: AliasLength

        :class:`ULONG`


    .. attribute:: DataOffset

        :class:`ULONG`

_API_SET_NAMESPACE_ARRAY
''''''''''''''''''''''''
.. class:: PAPI_SET_NAMESPACE_ARRAY

    Pointer to :class:`_API_SET_NAMESPACE_ARRAY`

.. class:: API_SET_NAMESPACE_ARRAY

    Alias for :class:`_API_SET_NAMESPACE_ARRAY`

.. class:: _API_SET_NAMESPACE_ARRAY

    .. attribute:: Version

        :class:`ULONG`


    .. attribute:: Size

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: Count

        :class:`ULONG`


    .. attribute:: Array

        :class:`API_SET_NAMESPACE_ENTRY` ``[ANYSIZE_ARRAY]``

_API_SET_VALUE_ENTRY_V2
'''''''''''''''''''''''
.. class:: PAPI_SET_VALUE_ENTRY_V2

    Pointer to :class:`_API_SET_VALUE_ENTRY_V2`

.. class:: API_SET_VALUE_ENTRY_V2

    Alias for :class:`_API_SET_VALUE_ENTRY_V2`

.. class:: _API_SET_VALUE_ENTRY_V2

    .. attribute:: NameOffset

        :class:`ULONG`


    .. attribute:: NameLength

        :class:`ULONG`


    .. attribute:: ValueOffset

        :class:`ULONG`


    .. attribute:: ValueLength

        :class:`ULONG`

_API_SET_VALUE_ARRAY_V2
'''''''''''''''''''''''
.. class:: API_SET_VALUE_ARRAY_V2

    Alias for :class:`_API_SET_VALUE_ARRAY_V2`

.. class:: PAPI_SET_VALUE_ARRAY_V2

    Pointer to :class:`_API_SET_VALUE_ARRAY_V2`

.. class:: _API_SET_VALUE_ARRAY_V2

    .. attribute:: Count

        :class:`ULONG`


    .. attribute:: Array

        :class:`API_SET_VALUE_ENTRY_V2` ``[ANYSIZE_ARRAY]``

_API_SET_NAMESPACE_ENTRY_V2
'''''''''''''''''''''''''''
.. class:: PAPI_SET_NAMESPACE_ENTRY_V2

    Pointer to :class:`_API_SET_NAMESPACE_ENTRY_V2`

.. class:: API_SET_NAMESPACE_ENTRY_V2

    Alias for :class:`_API_SET_NAMESPACE_ENTRY_V2`

.. class:: _API_SET_NAMESPACE_ENTRY_V2

    .. attribute:: NameOffset

        :class:`ULONG`


    .. attribute:: NameLength

        :class:`ULONG`


    .. attribute:: DataOffset

        :class:`ULONG`

_API_SET_NAMESPACE_ARRAY_V2
'''''''''''''''''''''''''''
.. class:: API_SET_NAMESPACE_ARRAY_V2

    Alias for :class:`_API_SET_NAMESPACE_ARRAY_V2`

.. class:: PAPI_SET_NAMESPACE_ARRAY_V2

    Pointer to :class:`_API_SET_NAMESPACE_ARRAY_V2`

.. class:: _API_SET_NAMESPACE_ARRAY_V2

    .. attribute:: Version

        :class:`ULONG`


    .. attribute:: Count

        :class:`ULONG`


    .. attribute:: Array

        :class:`API_SET_NAMESPACE_ENTRY_V2` ``[ANYSIZE_ARRAY]``

_API_SET_VALUE_ARRAY_V4
'''''''''''''''''''''''
.. class:: API_SET_VALUE_ARRAY_V4

    Alias for :class:`_API_SET_VALUE_ARRAY_V4`

.. class:: PAPI_SET_VALUE_ARRAY_V2

    Pointer to :class:`_API_SET_VALUE_ARRAY_V4`

.. class:: _API_SET_VALUE_ARRAY_V4

    .. attribute:: GuessFlags

        :class:`ULONG`


    .. attribute:: Count

        :class:`ULONG`


    .. attribute:: Array

        :class:`API_SET_VALUE_ENTRY_V2` ``[ANYSIZE_ARRAY]``

_API_SET_NAMESPACE_ARRAY_V4
'''''''''''''''''''''''''''
.. class:: API_SET_NAMESPACE_ARRAY_V4

    Alias for :class:`_API_SET_NAMESPACE_ARRAY_V4`

.. class:: PAPI_SET_NAMESPACE_ARRAY_V4

    Pointer to :class:`_API_SET_NAMESPACE_ARRAY_V4`

.. class:: _API_SET_NAMESPACE_ARRAY_V4

    .. attribute:: Version

        :class:`ULONG`


    .. attribute:: Size

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: Count

        :class:`ULONG`


    .. attribute:: Array

        :class:`API_SET_NAMESPACE_ENTRY` ``[ANYSIZE_ARRAY]``

_API_SET_NAMESPACE_ENTRY_V4
'''''''''''''''''''''''''''
.. class:: PAPI_SET_NAMESPACE_ENTRY_V4

    Pointer to :class:`_API_SET_NAMESPACE_ENTRY_V4`

.. class:: API_SET_NAMESPACE_ENTRY_V4

    Alias for :class:`_API_SET_NAMESPACE_ENTRY_V4`

.. class:: _API_SET_NAMESPACE_ENTRY_V4

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: NameOffset

        :class:`ULONG`


    .. attribute:: NameLength

        :class:`ULONG`


    .. attribute:: AliasOffset

        :class:`ULONG`


    .. attribute:: AliasLength

        :class:`ULONG`


    .. attribute:: DataOffset

        :class:`ULONG`

_API_SET_NAMESPACE_ENTRY_V6
'''''''''''''''''''''''''''
.. class:: API_SET_NAMESPACE_ENTRY_V6

    Alias for :class:`_API_SET_NAMESPACE_ENTRY_V6`

.. class:: _API_SET_NAMESPACE_ENTRY_V6

    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: NameOffset

        :class:`ULONG`


    .. attribute:: NameLength

        :class:`ULONG`


    .. attribute:: HashedLength

        :class:`ULONG`


    .. attribute:: ValueOffset

        :class:`ULONG`


    .. attribute:: ValueCount

        :class:`ULONG`

_API_SET_NAMESPACE_V6
'''''''''''''''''''''
.. class:: API_SET_NAMESPACE_V6

    Alias for :class:`_API_SET_NAMESPACE_V6`

.. class:: _API_SET_NAMESPACE_V6

    .. attribute:: Version

        :class:`ULONG`


    .. attribute:: Size

        :class:`ULONG`


    .. attribute:: Flags

        :class:`ULONG`


    .. attribute:: Count

        :class:`ULONG`


    .. attribute:: EntryOffset

        :class:`ULONG`


    .. attribute:: HashOffset

        :class:`ULONG`


    .. attribute:: HashFactor

        :class:`ULONG`

_BG_FILE_PROGRESS
'''''''''''''''''
.. class:: BG_FILE_PROGRESS

    Alias for :class:`_BG_FILE_PROGRESS`

.. class:: _BG_FILE_PROGRESS

    .. attribute:: BytesTotal

        :class:`UINT64`


    .. attribute:: BytesTransferred

        :class:`UINT64`


    .. attribute:: Completed

        :class:`BOOL`

_BG_JOB_PROGRESS
''''''''''''''''
.. class:: BG_JOB_PROGRESS

    Alias for :class:`_BG_JOB_PROGRESS`

.. class:: _BG_JOB_PROGRESS

    .. attribute:: BytesTotal

        :class:`UINT64`


    .. attribute:: BytesTransferred

        :class:`UINT64`


    .. attribute:: FilesTotal

        :class:`ULONG`


    .. attribute:: FilesTransferred

        :class:`ULONG`

_BG_FILE_INFO
'''''''''''''
.. class:: BG_FILE_INFO

    Alias for :class:`_BG_FILE_INFO`

.. class:: _BG_FILE_INFO

    .. attribute:: RemoteName

        :class:`LPWSTR`


    .. attribute:: LocalName

        :class:`LPWSTR`

_BG_JOB_TIMES
'''''''''''''
.. class:: BG_JOB_TIMES

    Alias for :class:`_BG_JOB_TIMES`

.. class:: _BG_JOB_TIMES

    .. attribute:: CreationTime

        :class:`FILETIME`


    .. attribute:: ModificationTime

        :class:`FILETIME`


    .. attribute:: TransferCompletionTime

        :class:`FILETIME`

_EVENTLOGRECORD
'''''''''''''''
.. class:: PEVENTLOGRECORD

    Pointer to :class:`_EVENTLOGRECORD`

.. class:: EVENTLOGRECORD

    Alias for :class:`_EVENTLOGRECORD`

.. class:: _EVENTLOGRECORD

    .. attribute:: Length

        :class:`DWORD`


    .. attribute:: Reserved

        :class:`DWORD`


    .. attribute:: RecordNumber

        :class:`DWORD`


    .. attribute:: TimeGenerated

        :class:`DWORD`


    .. attribute:: TimeWritten

        :class:`DWORD`


    .. attribute:: EventID

        :class:`DWORD`


    .. attribute:: EventType

        :class:`WORD`


    .. attribute:: NumStrings

        :class:`WORD`


    .. attribute:: EventCategory

        :class:`WORD`


    .. attribute:: ReservedFlags

        :class:`WORD`


    .. attribute:: ClosingRecordNumber

        :class:`DWORD`


    .. attribute:: StringOffset

        :class:`DWORD`


    .. attribute:: UserSidLength

        :class:`DWORD`


    .. attribute:: UserSidOffset

        :class:`DWORD`


    .. attribute:: DataLength

        :class:`DWORD`


    .. attribute:: DataOffset

        :class:`DWORD`

_EVENTLOG_FULL_INFORMATION
''''''''''''''''''''''''''
.. class:: EVENTLOG_FULL_INFORMATION

    Alias for :class:`_EVENTLOG_FULL_INFORMATION`

.. class:: LPEVENTLOG_FULL_INFORMATION

    Pointer to :class:`_EVENTLOG_FULL_INFORMATION`

.. class:: _EVENTLOG_FULL_INFORMATION

    .. attribute:: dwFull

        :class:`DWORD`

_ANON_evt_variant_sub_union
'''''''''''''''''''''''''''
.. class:: _ANON_evt_variant_sub_union

    .. attribute:: BooleanVal

        :class:`BOOL`


    .. attribute:: SByteVal

        :class:`INT8`


    .. attribute:: Int16Val

        :class:`INT16`


    .. attribute:: Int32Val

        :class:`INT32`


    .. attribute:: Int64Val

        :class:`INT64`


    .. attribute:: ByteVal

        :class:`UINT8`


    .. attribute:: UInt16Val

        :class:`UINT16`


    .. attribute:: UInt32Val

        :class:`UINT32`


    .. attribute:: UInt64Val

        :class:`UINT64`


    .. attribute:: SingleVal

        :class:`FLOAT`


    .. attribute:: DoubleVal

        :class:`DOUBLE`


    .. attribute:: FileTimeVal

        :class:`ULONGLONG`


    .. attribute:: SysTimeVal

        :class:`SYSTEMTIME`


    .. attribute:: GuidVal

        :class:`GUID`


    .. attribute:: StringVal

        :class:`LPCWSTR`


    .. attribute:: AnsiStringVal

        :class:`LPCSTR`


    .. attribute:: BinaryVal

        :class:`PBYTE`


    .. attribute:: SidVal

        :class:`PSID`


    .. attribute:: SizeTVal

        :class:`SIZE_T`


    .. attribute:: EvtHandleVal

        :class:`EVT_HANDLE`


    .. attribute:: BooleanArr

        :class:`BOOL`


    .. attribute:: SByteArr

        :class:`INT8`


    .. attribute:: Int16Arr

        :class:`INT16`


    .. attribute:: Int32Arr

        :class:`INT32`


    .. attribute:: Int64Arr

        :class:`INT64`


    .. attribute:: ByteArr

        :class:`UINT8`


    .. attribute:: UInt16Arr

        :class:`UINT16`


    .. attribute:: UInt32Arr

        :class:`UINT32`


    .. attribute:: UInt64Arr

        :class:`UINT64`


    .. attribute:: SingleArr

        :class:`FLOAT`


    .. attribute:: DoubleArr

        :class:`DOUBLE`


    .. attribute:: FileTimeArr

        :class:`FILETIME`


    .. attribute:: SysTimeArr

        :class:`SYSTEMTIME`


    .. attribute:: GuidArr

        :class:`GUID`


    .. attribute:: StringArr

        :class:`LPWSTR`


    .. attribute:: AnsiStringArr

        :class:`LPSTR`


    .. attribute:: SidArr

        :class:`PSID`


    .. attribute:: SizeTArr

        :class:`SIZE_T`


    .. attribute:: XmlVal

        :class:`LPCWSTR`


    .. attribute:: XmlValArr

        :class:`LPCWSTR`

_EVT_VARIANT
''''''''''''
.. class:: PEVT_VARIANT

    Pointer to :class:`_EVT_VARIANT`

.. class:: EVT_VARIANT

    Alias for :class:`_EVT_VARIANT`

.. class:: _EVT_VARIANT

    .. attribute:: _VARIANT_VALUE

        :class:`_ANON_evt_variant_sub_union`


    .. attribute:: Count

        :class:`DWORD`


    .. attribute:: Type

        :class:`DWORD`

_FILE_INTERNAL_INFORMATION
''''''''''''''''''''''''''
.. class:: FILE_INTERNAL_INFORMATION

    Alias for :class:`_FILE_INTERNAL_INFORMATION`

.. class:: PFILE_INTERNAL_INFORMATION

    Pointer to :class:`_FILE_INTERNAL_INFORMATION`

.. class:: _FILE_INTERNAL_INFORMATION

    .. attribute:: IndexNumber

        :class:`LARGE_INTEGER`

_FILE_ALIGNMENT_INFORMATION
'''''''''''''''''''''''''''
.. class:: PFILE_ALIGNMENT_INFORMATION

    Pointer to :class:`_FILE_ALIGNMENT_INFORMATION`

.. class:: FILE_ALIGNMENT_INFORMATION

    Alias for :class:`_FILE_ALIGNMENT_INFORMATION`

.. class:: _FILE_ALIGNMENT_INFORMATION

    .. attribute:: AlignmentRequirement

        :class:`ULONG`

_FILE_ATTRIBUTE_TAG_INFORMATION
'''''''''''''''''''''''''''''''
.. class:: PFILE_ATTRIBUTE_TAG_INFORMATION

    Pointer to :class:`_FILE_ATTRIBUTE_TAG_INFORMATION`

.. class:: FILE_ATTRIBUTE_TAG_INFORMATION

    Alias for :class:`_FILE_ATTRIBUTE_TAG_INFORMATION`

.. class:: _FILE_ATTRIBUTE_TAG_INFORMATION

    .. attribute:: FileAttributes

        :class:`ULONG`


    .. attribute:: ReparseTag

        :class:`ULONG`

_FILE_BASIC_INFORMATION
'''''''''''''''''''''''
.. class:: FILE_BASIC_INFORMATION

    Alias for :class:`_FILE_BASIC_INFORMATION`

.. class:: PFILE_BASIC_INFORMATION

    Pointer to :class:`_FILE_BASIC_INFORMATION`

.. class:: _FILE_BASIC_INFORMATION

    .. attribute:: CreationTime

        :class:`LARGE_INTEGER`


    .. attribute:: LastAccessTime

        :class:`LARGE_INTEGER`


    .. attribute:: LastWriteTime

        :class:`LARGE_INTEGER`


    .. attribute:: ChangeTime

        :class:`LARGE_INTEGER`


    .. attribute:: FileAttributes

        :class:`ULONG`

_FILE_EA_INFORMATION
''''''''''''''''''''
.. class:: PFILE_EA_INFORMATION

    Pointer to :class:`_FILE_EA_INFORMATION`

.. class:: FILE_EA_INFORMATION

    Alias for :class:`_FILE_EA_INFORMATION`

.. class:: _FILE_EA_INFORMATION

    .. attribute:: EaSize

        :class:`ULONG`

_FILE_IO_PRIORITY_HINT_INFORMATION
''''''''''''''''''''''''''''''''''
.. class:: PFILE_IO_PRIORITY_HINT_INFORMATION

    Pointer to :class:`_FILE_IO_PRIORITY_HINT_INFORMATION`

.. class:: FILE_IO_PRIORITY_HINT_INFORMATION

    Alias for :class:`_FILE_IO_PRIORITY_HINT_INFORMATION`

.. class:: _FILE_IO_PRIORITY_HINT_INFORMATION

    .. attribute:: PriorityHint

        :class:`IO_PRIORITY_HINT`

_FILE_MODE_INFORMATION
''''''''''''''''''''''
.. class:: PFILE_MODE_INFORMATION

    Pointer to :class:`_FILE_MODE_INFORMATION`

.. class:: FILE_MODE_INFORMATION

    Alias for :class:`_FILE_MODE_INFORMATION`

.. class:: _FILE_MODE_INFORMATION

    .. attribute:: Mode

        :class:`ULONG`

_FILE_NAME_INFORMATION
''''''''''''''''''''''
.. class:: PFILE_NAME_INFORMATION

    Pointer to :class:`_FILE_NAME_INFORMATION`

.. class:: FILE_NAME_INFORMATION

    Alias for :class:`_FILE_NAME_INFORMATION`

.. class:: _FILE_NAME_INFORMATION

    .. attribute:: FileNameLength

        :class:`ULONG`


    .. attribute:: FileName

        :class:`WCHAR` ``[1]``

_FILE_NETWORK_OPEN_INFORMATION
''''''''''''''''''''''''''''''
.. class:: PFILE_NETWORK_OPEN_INFORMATION

    Pointer to :class:`_FILE_NETWORK_OPEN_INFORMATION`

.. class:: FILE_NETWORK_OPEN_INFORMATION

    Alias for :class:`_FILE_NETWORK_OPEN_INFORMATION`

.. class:: _FILE_NETWORK_OPEN_INFORMATION

    .. attribute:: CreationTime

        :class:`LARGE_INTEGER`


    .. attribute:: LastAccessTime

        :class:`LARGE_INTEGER`


    .. attribute:: LastWriteTime

        :class:`LARGE_INTEGER`


    .. attribute:: ChangeTime

        :class:`LARGE_INTEGER`


    .. attribute:: AllocationSize

        :class:`LARGE_INTEGER`


    .. attribute:: EndOfFile

        :class:`LARGE_INTEGER`


    .. attribute:: FileAttributes

        :class:`ULONG`

_FILE_STANDARD_INFORMATION
''''''''''''''''''''''''''
.. class:: FILE_STANDARD_INFORMATION

    Alias for :class:`_FILE_STANDARD_INFORMATION`

.. class:: PFILE_STANDARD_INFORMATION

    Pointer to :class:`_FILE_STANDARD_INFORMATION`

.. class:: _FILE_STANDARD_INFORMATION

    .. attribute:: AllocationSize

        :class:`LARGE_INTEGER`


    .. attribute:: EndOfFile

        :class:`LARGE_INTEGER`


    .. attribute:: NumberOfLinks

        :class:`ULONG`


    .. attribute:: DeletePending

        :class:`BOOLEAN`


    .. attribute:: Directory

        :class:`BOOLEAN`

_FILE_ACCESS_INFORMATION
''''''''''''''''''''''''
.. class:: FILE_ACCESS_INFORMATION

    Alias for :class:`_FILE_ACCESS_INFORMATION`

.. class:: PFILE_ACCESS_INFORMATION

    Pointer to :class:`_FILE_ACCESS_INFORMATION`

.. class:: _FILE_ACCESS_INFORMATION

    .. attribute:: AccessFlags

        :class:`ACCESS_MASK`

_FILE_POSITION_INFORMATION
''''''''''''''''''''''''''
.. class:: PFILE_POSITION_INFORMATION

    Pointer to :class:`_FILE_POSITION_INFORMATION`

.. class:: FILE_POSITION_INFORMATION

    Alias for :class:`_FILE_POSITION_INFORMATION`

.. class:: _FILE_POSITION_INFORMATION

    .. attribute:: CurrentByteOffset

        :class:`LARGE_INTEGER`

_FILE_IS_REMOTE_DEVICE_INFORMATION
''''''''''''''''''''''''''''''''''
.. class:: FILE_IS_REMOTE_DEVICE_INFORMATION

    Alias for :class:`_FILE_IS_REMOTE_DEVICE_INFORMATION`

.. class:: PFILE_IS_REMOTE_DEVICE_INFORMATION

    Pointer to :class:`_FILE_IS_REMOTE_DEVICE_INFORMATION`

.. class:: _FILE_IS_REMOTE_DEVICE_INFORMATION

    .. attribute:: IsRemote

        :class:`BOOLEAN`

_FILE_ALL_INFORMATION
'''''''''''''''''''''
.. class:: PFILE_ALL_INFORMATION

    Pointer to :class:`_FILE_ALL_INFORMATION`

.. class:: FILE_ALL_INFORMATION

    Alias for :class:`_FILE_ALL_INFORMATION`

.. class:: _FILE_ALL_INFORMATION

    .. attribute:: BasicInformation

        :class:`FILE_BASIC_INFORMATION`


    .. attribute:: StandardInformation

        :class:`FILE_STANDARD_INFORMATION`


    .. attribute:: InternalInformation

        :class:`FILE_INTERNAL_INFORMATION`


    .. attribute:: EaInformation

        :class:`FILE_EA_INFORMATION`


    .. attribute:: AccessInformation

        :class:`FILE_ACCESS_INFORMATION`


    .. attribute:: PositionInformation

        :class:`FILE_POSITION_INFORMATION`


    .. attribute:: ModeInformation

        :class:`FILE_MODE_INFORMATION`


    .. attribute:: AlignmentInformation

        :class:`FILE_ALIGNMENT_INFORMATION`


    .. attribute:: NameInformation

        :class:`FILE_NAME_INFORMATION`

Simple types
''''''''''''
.. autoclass:: VOID

.. autoclass:: BYTE

.. autoclass:: PWSTR

.. autoclass:: PCWSTR

.. autoclass:: SIZE_T

.. class:: PSIZE_T

    Pointer to :class:`SIZE_T`

.. autoclass:: PVOID

.. autoclass:: NTSTATUS

.. autoclass:: SECURITY_INFORMATION

.. class:: PSECURITY_INFORMATION

    Pointer to :class:`SECURITY_INFORMATION`

.. class:: PULONG

    Pointer to :class:`ULONG`

.. class:: PDWORD

    Pointer to :class:`DWORD`

.. class:: LPDWORD

    Pointer to :class:`DWORD`

.. class:: LPBYTE

    Pointer to :class:`BYTE`

.. autoclass:: ULONG_PTR

.. autoclass:: LONG_PTR

.. autoclass:: DWORD_PTR

.. autoclass:: KAFFINITY

.. autoclass:: KPRIORITY

.. autoclass:: CHAR

.. autoclass:: UCHAR

.. autoclass:: CSHORT

.. autoclass:: VARTYPE

.. class:: PUSHORT

    Pointer to :class:`USHORT`

.. class:: PBOOL

    Pointer to :class:`BOOL`

.. autoclass:: PSTR

.. autoclass:: PCSTR

.. autoclass:: va_list

.. autoclass:: BSTR

.. autoclass:: OLECHAR

.. autoclass:: POLECHAR

.. class:: PUCHAR

    Pointer to :class:`UCHAR`

.. autoclass:: double

.. autoclass:: DATE

.. autoclass:: PSID

.. autoclass:: ULONGLONG

.. class:: PULONGLONG

    Pointer to :class:`ULONGLONG`

.. autoclass:: LONGLONG

.. autoclass:: ULONG64

.. autoclass:: UINT64

.. autoclass:: LONG64

.. class:: PLARGE_INTEGER

    Pointer to :class:`LARGE_INTEGER`

.. autoclass:: DWORD64

.. class:: PDWORD64

    Pointer to :class:`DWORD64`

.. autoclass:: SCODE

.. autoclass:: CIMTYPE

.. autoclass:: NET_IFINDEX

.. autoclass:: IF_INDEX

.. autoclass:: IFTYPE

.. class:: PULONG64

    Pointer to :class:`ULONG64`

.. class:: PBYTE

    Pointer to :class:`BYTE`

.. class:: PUINT

    Pointer to :class:`UINT`

.. class:: PHKEY

    Pointer to :class:`HKEY`

.. autoclass:: ACCESS_MASK

.. autoclass:: REGSAM

.. class:: PBOOLEAN

    Pointer to :class:`BOOLEAN`

.. autoclass:: SECURITY_CONTEXT_TRACKING_MODE

.. autoclass:: HCRYPTPROV_LEGACY

.. autoclass:: HCRYPTKEY

.. autoclass:: HCRYPTPROV

.. autoclass:: HCRYPTHASH

.. autoclass:: ALG_ID

.. autoclass:: DISPID

.. autoclass:: MEMBERID

.. autoclass:: LRESULT

.. autoclass:: PSECURITY_DESCRIPTOR

.. class:: LPUNKNOWN

    Pointer to :class:`PVOID`

.. class:: LPFILETIME

    Pointer to :class:`FILETIME`

.. class:: LPPOINT

    Pointer to :class:`POINT`

.. class:: LPRECT

    Pointer to :class:`RECT`

.. autoclass:: SPC_UUID

.. autoclass:: DEVICE_TYPE

.. autoclass:: PWINDBG_EXTENSION_APIS32

.. autoclass:: PWINDBG_EXTENSION_APIS64

.. autoclass:: INT8

.. autoclass:: INT16

.. autoclass:: INT32

.. autoclass:: INT64

.. autoclass:: UINT8

.. autoclass:: UINT16

.. autoclass:: UINT32

.. autoclass:: UINT64

.. class:: PHANDLE

    Pointer to :class:`HANDLE`

.. autoclass:: HCATADMIN

.. autoclass:: HCATINFO

.. autoclass:: HCERTCHAINENGINE

.. class:: LPHANDLE

    Pointer to :class:`HANDLE`

.. autoclass:: ALPC_HANDLE

.. class:: PALPC_HANDLE

    Pointer to :class:`ALPC_HANDLE`

.. autoclass:: HCURSOR

.. autoclass:: HBRUSH

.. autoclass:: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE

.. autoclass:: EVT_HANDLE

.. autoclass:: EVT_OBJECT_ARRAY_PROPERTY_HANDLE

.. autoclass:: RPCOLEDATAREP

.. autoclass:: WNDPROC

.. autoclass:: LPPROC_THREAD_ATTRIBUTE_LIST

.. autoclass:: PPS_POST_PROCESS_INIT_ROUTINE

.. autoclass:: LPTHREAD_START_ROUTINE

.. autoclass:: WNDENUMPROC

.. autoclass:: PHANDLER_ROUTINE

.. autoclass:: FARPROC

.. autoclass:: PIO_APC_ROUTINE

.. autoclass:: PVECTORED_EXCEPTION_HANDLER

.. autoclass:: LPCONTEXT

.. autoclass:: HCERTSTORE

.. autoclass:: HCRYPTMSG

.. autoclass:: PALPC_PORT_ATTRIBUTES

.. autoclass:: PPORT_MESSAGE

WinEnums
--------
_CALLFRAME_COPY
'''''''''''''''
.. class:: CALLFRAME_COPY

    Alias for :class:`_CALLFRAME_COPY`


.. class:: _CALLFRAME_COPY


    .. attribute:: CALLFRAME_COPY_NESTED(1)


    .. attribute:: CALLFRAME_COPY_INDEPENDENT(2)

tagMSHLFLAGS
''''''''''''
.. class:: MSHLFLAGS

    Alias for :class:`tagMSHLFLAGS`


.. class:: tagMSHLFLAGS


    .. attribute:: MSHLFLAGS_NORMAL(0)


    .. attribute:: MSHLFLAGS_TABLESTRONG(1)


    .. attribute:: MSHLFLAGS_TABLEWEAK(2)


    .. attribute:: MSHLFLAGS_NOPING(4)

tagCALLFRAME_WALK
'''''''''''''''''
.. class:: CALLFRAME_WALK

    Alias for :class:`tagCALLFRAME_WALK`


.. class:: tagCALLFRAME_WALK


    .. attribute:: CALLFRAME_WALK_IN(1)


    .. attribute:: CALLFRAME_WALK_INOUT(2)


    .. attribute:: CALLFRAME_WALK_OUT(4)

_PROCESS_MITIGATION_POLICY
''''''''''''''''''''''''''
.. class:: PROCESS_MITIGATION_POLICY

    Alias for :class:`_PROCESS_MITIGATION_POLICY`


.. class:: PPROCESS_MITIGATION_POLICY

    Pointer to :class:`_PROCESS_MITIGATION_POLICY`


.. class:: _PROCESS_MITIGATION_POLICY


    .. attribute:: ProcessDEPPolicy(0)


    .. attribute:: ProcessASLRPolicy(1)


    .. attribute:: ProcessDynamicCodePolicy(2)


    .. attribute:: ProcessStrictHandleCheckPolicy(3)


    .. attribute:: ProcessSystemCallDisablePolicy(4)


    .. attribute:: ProcessMitigationOptionsMask(5)


    .. attribute:: ProcessExtensionPointDisablePolicy(6)


    .. attribute:: ProcessReserved1Policy(7)


    .. attribute:: ProcessSignaturePolicy(8)


    .. attribute:: MaxProcessMitigationPolicy(9)

_KEY_VALUE_INFORMATION_CLASS
''''''''''''''''''''''''''''
.. class:: KEY_VALUE_INFORMATION_CLASS

    Alias for :class:`_KEY_VALUE_INFORMATION_CLASS`


.. class:: _KEY_VALUE_INFORMATION_CLASS


    .. attribute:: KeyValueBasicInformation(0)


    .. attribute:: KeyValueFullInformation(1)


    .. attribute:: KeyValuePartialInformation(2)


    .. attribute:: KeyValueFullInformationAlign64(3)


    .. attribute:: KeyValuePartialInformationAlign64(4)


    .. attribute:: KeyValueLayerInformation(5)


    .. attribute:: MaxKeyValueInfoClass(6)

_TASK_ACTION_TYPE
'''''''''''''''''
.. class:: TASK_ACTION_TYPE

    Alias for :class:`_TASK_ACTION_TYPE`


.. class:: _TASK_ACTION_TYPE


    .. attribute:: TASK_ACTION_EXEC(0)


    .. attribute:: TASK_ACTION_COM_HANDLER(5)


    .. attribute:: TASK_ACTION_SEND_EMAIL(6)


    .. attribute:: TASK_ACTION_SHOW_MESSAGE(7)

_TASK_RUNLEVEL_TYPE
'''''''''''''''''''
.. class:: TASK_RUNLEVEL_TYPE

    Alias for :class:`_TASK_RUNLEVEL_TYPE`


.. class:: _TASK_RUNLEVEL_TYPE


    .. attribute:: TASK_RUNLEVEL_LUA(0)


    .. attribute:: TASK_RUNLEVEL_HIGHEST(1)

_TASK_LOGON_TYPE
''''''''''''''''
.. class:: TASK_LOGON_TYPE

    Alias for :class:`_TASK_LOGON_TYPE`


.. class:: _TASK_LOGON_TYPE


    .. attribute:: TASK_LOGON_NONE(0)


    .. attribute:: TASK_LOGON_PASSWORD(1)


    .. attribute:: TASK_LOGON_S4U(2)


    .. attribute:: TASK_LOGON_INTERACTIVE_TOKEN(3)


    .. attribute:: TASK_LOGON_GROUP(4)


    .. attribute:: TASK_LOGON_SERVICE_ACCOUNT(5)


    .. attribute:: TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD(6)

_TASK_STATE
'''''''''''
.. class:: TASK_STATE

    Alias for :class:`_TASK_STATE`


.. class:: _TASK_STATE


    .. attribute:: TASK_STATE_UNKNOWN(0)


    .. attribute:: TASK_STATE_DISABLED(1)


    .. attribute:: TASK_STATE_QUEUED(2)


    .. attribute:: TASK_STATE_READY(3)


    .. attribute:: TASK_STATE_RUNNING(4)

_TASK_INSTANCES_POLICY
''''''''''''''''''''''
.. class:: TASK_INSTANCES_POLICY

    Alias for :class:`_TASK_INSTANCES_POLICY`


.. class:: _TASK_INSTANCES_POLICY


    .. attribute:: TASK_INSTANCES_PARALLEL(0)


    .. attribute:: TASK_INSTANCES_QUEUE(1)


    .. attribute:: TASK_INSTANCES_IGNORE_NEW(2)


    .. attribute:: TASK_INSTANCES_STOP_EXISTING(3)

_TASK_COMPATIBILITY
'''''''''''''''''''
.. class:: TASK_COMPATIBILITY

    Alias for :class:`_TASK_COMPATIBILITY`


.. class:: _TASK_COMPATIBILITY


    .. attribute:: TASK_COMPATIBILITY_AT(0)


    .. attribute:: TASK_COMPATIBILITY_V1(1)


    .. attribute:: TASK_COMPATIBILITY_V2(2)

_TASK_TRIGGER_TYPE2
'''''''''''''''''''
.. class:: TASK_TRIGGER_TYPE2

    Alias for :class:`_TASK_TRIGGER_TYPE2`


.. class:: _TASK_TRIGGER_TYPE2


    .. attribute:: TASK_TRIGGER_EVENT(0)


    .. attribute:: TASK_TRIGGER_TIME(1)


    .. attribute:: TASK_TRIGGER_DAILY(2)


    .. attribute:: TASK_TRIGGER_WEEKLY(3)


    .. attribute:: TASK_TRIGGER_MONTHLY(4)


    .. attribute:: TASK_TRIGGER_MONTHLYDOW(5)


    .. attribute:: TASK_TRIGGER_IDLE(6)


    .. attribute:: TASK_TRIGGER_REGISTRATION(7)


    .. attribute:: TASK_TRIGGER_BOOT(8)


    .. attribute:: TASK_TRIGGER_LOGON(9)


    .. attribute:: TASK_TRIGGER_SESSION_STATE_CHANGE(11)

_TASK_ENUM_FLAGS
''''''''''''''''
.. class:: TASK_ENUM_FLAGS

    Alias for :class:`_TASK_ENUM_FLAGS`


.. class:: _TASK_ENUM_FLAGS


    .. attribute:: TASK_ENUM_HIDDEN(1)

_TASK_CREATION
''''''''''''''
.. class:: TASK_CREATION

    Alias for :class:`_TASK_CREATION`


.. class:: _TASK_CREATION


    .. attribute:: TASK_VALIDATE_ONLY(1)


    .. attribute:: TASK_CREATE(2)


    .. attribute:: TASK_UPDATE(4)


    .. attribute:: TASK_CREATE_OR_UPDATE(6)


    .. attribute:: TASK_DISABLE(8)


    .. attribute:: TASK_DONT_ADD_PRINCIPAL_ACE(16)


    .. attribute:: TASK_IGNORE_REGISTRATION_TRIGGERS(32)

TASK_RUN_FLAGS
''''''''''''''
.. class:: TASK_RUN_FLAGS

    Alias for :class:`TASK_RUN_FLAGS`


.. class:: TASK_RUN_FLAGS


    .. attribute:: TASK_RUN_NO_FLAGS(0)


    .. attribute:: TASK_RUN_AS_SELF(1)


    .. attribute:: TASK_RUN_IGNORE_CONSTRAINTS(2)


    .. attribute:: TASK_RUN_USE_SESSION_ID(4)


    .. attribute:: TASK_RUN_USER_SID(8)

_SYSTEM_INFORMATION_CLASS
'''''''''''''''''''''''''
.. class:: SYSTEM_INFORMATION_CLASS

    Alias for :class:`_SYSTEM_INFORMATION_CLASS`


.. class:: _SYSTEM_INFORMATION_CLASS


    .. attribute:: SystemBasicInformation(0)


    .. attribute:: SystemProcessorInformation(1)


    .. attribute:: SystemPerformanceInformation(2)


    .. attribute:: SystemTimeOfDayInformation(3)


    .. attribute:: SystemPathInformation(4)


    .. attribute:: SystemProcessInformation(5)


    .. attribute:: SystemCallCountInformation(6)


    .. attribute:: SystemDeviceInformation(7)


    .. attribute:: SystemProcessorPerformanceInformation(8)


    .. attribute:: SystemFlagsInformation(9)


    .. attribute:: SystemCallTimeInformation(10)


    .. attribute:: SystemModuleInformation(11)


    .. attribute:: SystemLocksInformation(12)


    .. attribute:: SystemStackTraceInformation(13)


    .. attribute:: SystemPagedPoolInformation(14)


    .. attribute:: SystemNonPagedPoolInformation(15)


    .. attribute:: SystemHandleInformation(16)


    .. attribute:: SystemObjectInformation(17)


    .. attribute:: SystemPageFileInformation(18)


    .. attribute:: SystemVdmInstemulInformation(19)


    .. attribute:: SystemVdmBopInformation(20)


    .. attribute:: SystemFileCacheInformation(21)


    .. attribute:: SystemPoolTagInformation(22)


    .. attribute:: SystemInterruptInformation(23)


    .. attribute:: SystemDpcBehaviorInformation(24)


    .. attribute:: SystemFullMemoryInformation(25)


    .. attribute:: SystemLoadGdiDriverInformation(26)


    .. attribute:: SystemUnloadGdiDriverInformation(27)


    .. attribute:: SystemTimeAdjustmentInformation(28)


    .. attribute:: SystemSummaryMemoryInformation(29)


    .. attribute:: SystemMirrorMemoryInformation(30)


    .. attribute:: SystemPerformanceTraceInformation(31)


    .. attribute:: SystemObsolete0(32)


    .. attribute:: SystemExceptionInformation(33)


    .. attribute:: SystemCrashDumpStateInformation(34)


    .. attribute:: SystemKernelDebuggerInformation(35)


    .. attribute:: SystemContextSwitchInformation(36)


    .. attribute:: SystemRegistryQuotaInformation(37)


    .. attribute:: SystemExtendServiceTableInformation(38)


    .. attribute:: SystemPrioritySeperation(39)


    .. attribute:: SystemVerifierAddDriverInformation(40)


    .. attribute:: SystemVerifierRemoveDriverInformation(41)


    .. attribute:: SystemProcessorIdleInformation(42)


    .. attribute:: SystemLegacyDriverInformation(43)


    .. attribute:: SystemCurrentTimeZoneInformation(44)


    .. attribute:: SystemLookasideInformation(45)


    .. attribute:: SystemTimeSlipNotification(46)


    .. attribute:: SystemSessionCreate(47)


    .. attribute:: SystemSessionDetach(48)


    .. attribute:: SystemSessionInformation(49)


    .. attribute:: SystemRangeStartInformation(50)


    .. attribute:: SystemVerifierInformation(51)


    .. attribute:: SystemVerifierThunkExtend(52)


    .. attribute:: SystemSessionProcessInformation(53)


    .. attribute:: SystemLoadGdiDriverInSystemSpace(54)


    .. attribute:: SystemNumaProcessorMap(55)


    .. attribute:: SystemPrefetcherInformation(56)


    .. attribute:: SystemExtendedProcessInformation(57)


    .. attribute:: SystemRecommendedSharedDataAlignment(58)


    .. attribute:: SystemComPlusPackage(59)


    .. attribute:: SystemNumaAvailableMemory(60)


    .. attribute:: SystemProcessorPowerInformation(61)


    .. attribute:: SystemEmulationBasicInformation(62)


    .. attribute:: SystemEmulationProcessorInformation(63)


    .. attribute:: SystemExtendedHandleInformation(64)


    .. attribute:: SystemLostDelayedWriteInformation(65)


    .. attribute:: SystemBigPoolInformation(66)


    .. attribute:: SystemSessionPoolTagInformation(67)


    .. attribute:: SystemSessionMappedViewInformation(68)


    .. attribute:: SystemHotpatchInformation(69)


    .. attribute:: SystemObjectSecurityMode(70)


    .. attribute:: SystemWatchdogTimerHandler(71)


    .. attribute:: SystemWatchdogTimerInformation(72)


    .. attribute:: SystemLogicalProcessorInformation(73)


    .. attribute:: SystemWow64SharedInformation(74)


    .. attribute:: SystemRegisterFirmwareTableInformationHandler(75)


    .. attribute:: SystemFirmwareTableInformation(76)


    .. attribute:: SystemModuleInformationEx(77)


    .. attribute:: SystemVerifierTriageInformation(78)


    .. attribute:: SystemSuperfetchInformation(79)


    .. attribute:: SystemMemoryListInformation(80)


    .. attribute:: SystemFileCacheInformationEx(81)


    .. attribute:: MaxSystemInfoClass(82)

_WELL_KNOWN_SID_TYPE
''''''''''''''''''''
.. class:: WELL_KNOWN_SID_TYPE

    Alias for :class:`_WELL_KNOWN_SID_TYPE`


.. class:: _WELL_KNOWN_SID_TYPE


    .. attribute:: WinNullSid(0)


    .. attribute:: WinWorldSid(1)


    .. attribute:: WinLocalSid(2)


    .. attribute:: WinCreatorOwnerSid(3)


    .. attribute:: WinCreatorGroupSid(4)


    .. attribute:: WinCreatorOwnerServerSid(5)


    .. attribute:: WinCreatorGroupServerSid(6)


    .. attribute:: WinNtAuthoritySid(7)


    .. attribute:: WinDialupSid(8)


    .. attribute:: WinNetworkSid(9)


    .. attribute:: WinBatchSid(10)


    .. attribute:: WinInteractiveSid(11)


    .. attribute:: WinServiceSid(12)


    .. attribute:: WinAnonymousSid(13)


    .. attribute:: WinProxySid(14)


    .. attribute:: WinEnterpriseControllersSid(15)


    .. attribute:: WinSelfSid(16)


    .. attribute:: WinAuthenticatedUserSid(17)


    .. attribute:: WinRestrictedCodeSid(18)


    .. attribute:: WinTerminalServerSid(19)


    .. attribute:: WinRemoteLogonIdSid(20)


    .. attribute:: WinLogonIdsSid(21)


    .. attribute:: WinLocalSystemSid(22)


    .. attribute:: WinLocalServiceSid(23)


    .. attribute:: WinNetworkServiceSid(24)


    .. attribute:: WinBuiltinDomainSid(25)


    .. attribute:: WinBuiltinAdministratorsSid(26)


    .. attribute:: WinBuiltinUsersSid(27)


    .. attribute:: WinBuiltinGuestsSid(28)


    .. attribute:: WinBuiltinPowerUsersSid(29)


    .. attribute:: WinBuiltinAccountOperatorsSid(30)


    .. attribute:: WinBuiltinSystemOperatorsSid(31)


    .. attribute:: WinBuiltinPrintOperatorsSid(32)


    .. attribute:: WinBuiltinBackupOperatorsSid(33)


    .. attribute:: WinBuiltinReplicatorSid(34)


    .. attribute:: WinBuiltinPreWindows2000CompatibleAccessSid(35)


    .. attribute:: WinBuiltinRemoteDesktopUsersSid(36)


    .. attribute:: WinBuiltinNetworkConfigurationOperatorsSid(37)


    .. attribute:: WinAccountAdministratorSid(38)


    .. attribute:: WinAccountGuestSid(39)


    .. attribute:: WinAccountKrbtgtSid(40)


    .. attribute:: WinAccountDomainAdminsSid(41)


    .. attribute:: WinAccountDomainUsersSid(42)


    .. attribute:: WinAccountDomainGuestsSid(43)


    .. attribute:: WinAccountComputersSid(44)


    .. attribute:: WinAccountControllersSid(45)


    .. attribute:: WinAccountCertAdminsSid(46)


    .. attribute:: WinAccountSchemaAdminsSid(47)


    .. attribute:: WinAccountEnterpriseAdminsSid(48)


    .. attribute:: WinAccountPolicyAdminsSid(49)


    .. attribute:: WinAccountRasAndIasServersSid(50)


    .. attribute:: WinNTLMAuthenticationSid(51)


    .. attribute:: WinDigestAuthenticationSid(52)


    .. attribute:: WinSChannelAuthenticationSid(53)


    .. attribute:: WinThisOrganizationSid(54)


    .. attribute:: WinOtherOrganizationSid(55)


    .. attribute:: WinBuiltinIncomingForestTrustBuildersSid(56)


    .. attribute:: WinBuiltinPerfMonitoringUsersSid(57)


    .. attribute:: WinBuiltinPerfLoggingUsersSid(58)


    .. attribute:: WinBuiltinAuthorizationAccessSid(59)


    .. attribute:: WinBuiltinTerminalServerLicenseServersSid(60)


    .. attribute:: WinBuiltinDCOMUsersSid(61)


    .. attribute:: WinBuiltinIUsersSid(62)


    .. attribute:: WinIUserSid(63)


    .. attribute:: WinBuiltinCryptoOperatorsSid(64)


    .. attribute:: WinUntrustedLabelSid(65)


    .. attribute:: WinLowLabelSid(66)


    .. attribute:: WinMediumLabelSid(67)


    .. attribute:: WinHighLabelSid(68)


    .. attribute:: WinSystemLabelSid(69)


    .. attribute:: WinWriteRestrictedCodeSid(70)


    .. attribute:: WinCreatorOwnerRightsSid(71)


    .. attribute:: WinCacheablePrincipalsGroupSid(72)


    .. attribute:: WinNonCacheablePrincipalsGroupSid(73)


    .. attribute:: WinEnterpriseReadonlyControllersSid(74)


    .. attribute:: WinAccountReadonlyControllersSid(75)


    .. attribute:: WinBuiltinEventLogReadersGroup(76)


    .. attribute:: WinNewEnterpriseReadonlyControllersSid(77)


    .. attribute:: WinBuiltinCertSvcDComAccessGroup(78)


    .. attribute:: WinMediumPlusLabelSid(79)


    .. attribute:: WinLocalLogonSid(80)


    .. attribute:: WinConsoleLogonSid(81)


    .. attribute:: WinThisOrganizationCertificateSid(82)


    .. attribute:: WinApplicationPackageAuthoritySid(83)


    .. attribute:: WinBuiltinAnyPackageSid(84)


    .. attribute:: WinCapabilityInternetClientSid(85)


    .. attribute:: WinCapabilityInternetClientServerSid(86)


    .. attribute:: WinCapabilityPrivateNetworkClientServerSid(87)


    .. attribute:: WinCapabilityPicturesLibrarySid(88)


    .. attribute:: WinCapabilityVideosLibrarySid(89)


    .. attribute:: WinCapabilityMusicLibrarySid(90)


    .. attribute:: WinCapabilityDocumentsLibrarySid(91)


    .. attribute:: WinCapabilitySharedUserCertificatesSid(92)


    .. attribute:: WinCapabilityEnterpriseAuthenticationSid(93)


    .. attribute:: WinCapabilityRemovableStorageSid(94)

_SECTION_INHERIT
''''''''''''''''
.. class:: SECTION_INHERIT

    Alias for :class:`_SECTION_INHERIT`


.. class:: _SECTION_INHERIT


    .. attribute:: ViewShare(1)


    .. attribute:: ViewUnmap(2)

_PROCESSINFOCLASS
'''''''''''''''''
.. class:: PROCESS_INFORMATION_CLASS

    Alias for :class:`_PROCESSINFOCLASS`


.. class:: PROCESSINFOCLASS

    Alias for :class:`_PROCESSINFOCLASS`


.. class:: _PROCESSINFOCLASS


    .. attribute:: ProcessBasicInformation(0)


    .. attribute:: ProcessQuotaLimits(1)


    .. attribute:: ProcessIoCounters(2)


    .. attribute:: ProcessVmCounters(3)


    .. attribute:: ProcessTimes(4)


    .. attribute:: ProcessBasePriority(5)


    .. attribute:: ProcessRaisePriority(6)


    .. attribute:: ProcessDebugPort(7)


    .. attribute:: ProcessExceptionPort(8)


    .. attribute:: ProcessAccessToken(9)


    .. attribute:: ProcessLdtInformation(10)


    .. attribute:: ProcessLdtSize(11)


    .. attribute:: ProcessDefaultHardErrorMode(12)


    .. attribute:: ProcessIoPortHandlers(13)


    .. attribute:: ProcessPooledUsageAndLimits(14)


    .. attribute:: ProcessWorkingSetWatch(15)


    .. attribute:: ProcessUserModeIOPL(16)


    .. attribute:: ProcessEnableAlignmentFaultFixup(17)


    .. attribute:: ProcessPriorityClass(18)


    .. attribute:: ProcessWx86Information(19)


    .. attribute:: ProcessHandleCount(20)


    .. attribute:: ProcessAffinityMask(21)


    .. attribute:: ProcessPriorityBoost(22)


    .. attribute:: ProcessDeviceMap(23)


    .. attribute:: ProcessSessionInformation(24)


    .. attribute:: ProcessForegroundInformation(25)


    .. attribute:: ProcessWow64Information(26)


    .. attribute:: ProcessImageFileName(27)


    .. attribute:: ProcessLUIDDeviceMapsEnabled(28)


    .. attribute:: ProcessBreakOnTermination(29)


    .. attribute:: ProcessDebugObjectHandle(30)


    .. attribute:: ProcessDebugFlags(31)


    .. attribute:: ProcessHandleTracing(32)


    .. attribute:: ProcessIoPriority(33)


    .. attribute:: ProcessExecuteFlags(34)


    .. attribute:: ProcessResourceManagement(35)


    .. attribute:: ProcessCookie(36)


    .. attribute:: ProcessImageInformation(37)


    .. attribute:: ProcessInformation38(38)


    .. attribute:: ProcessInformation39(39)


    .. attribute:: ProcessInstrumentationCallback(40)


    .. attribute:: MaxProcessInfoClass(41)

_MEMORY_INFORMATION_CLASS
'''''''''''''''''''''''''
.. class:: MEMORY_INFORMATION_CLASS

    Alias for :class:`_MEMORY_INFORMATION_CLASS`


.. class:: _MEMORY_INFORMATION_CLASS


    .. attribute:: MemoryBasicInformation(0)


    .. attribute:: MemoryWorkingSetList(1)


    .. attribute:: MemorySectionName(2)


    .. attribute:: MemoryBasicVlmInformation(3)


    .. attribute:: MemoryWorkingSetListEx(4)

_THREAD_INFORMATION_CLASS
'''''''''''''''''''''''''
.. class:: THREAD_INFORMATION_CLASS

    Alias for :class:`_THREAD_INFORMATION_CLASS`


.. class:: PTHREAD_INFORMATION_CLASS

    Pointer to :class:`_THREAD_INFORMATION_CLASS`


.. class:: _THREAD_INFORMATION_CLASS


    .. attribute:: ThreadBasicInformation(0)


    .. attribute:: ThreadTimes(1)


    .. attribute:: ThreadPriority(2)


    .. attribute:: ThreadBasePriority(3)


    .. attribute:: ThreadAffinityMask(4)


    .. attribute:: ThreadImpersonationToken(5)


    .. attribute:: ThreadDescriptorTableEntry(6)


    .. attribute:: ThreadEnableAlignmentFaultFixup(7)


    .. attribute:: ThreadEventPair(8)


    .. attribute:: ThreadQuerySetWin32StartAddress(9)


    .. attribute:: ThreadZeroTlsCell(10)


    .. attribute:: ThreadPerformanceCount(11)


    .. attribute:: ThreadAmILastThread(12)


    .. attribute:: ThreadIdealProcessor(13)


    .. attribute:: ThreadPriorityBoost(14)


    .. attribute:: ThreadSetTlsArrayAddress(15)


    .. attribute:: ThreadIsIoPending(16)


    .. attribute:: ThreadHideFromDebugger(17)

_TCP_TABLE_CLASS
''''''''''''''''
.. class:: TCP_TABLE_CLASS

    Alias for :class:`_TCP_TABLE_CLASS`


.. class:: _TCP_TABLE_CLASS


    .. attribute:: TCP_TABLE_BASIC_LISTENER(0)


    .. attribute:: TCP_TABLE_BASIC_CONNECTIONS(1)


    .. attribute:: TCP_TABLE_BASIC_ALL(2)


    .. attribute:: TCP_TABLE_OWNER_PID_LISTENER(3)


    .. attribute:: TCP_TABLE_OWNER_PID_CONNECTIONS(4)


    .. attribute:: TCP_TABLE_OWNER_PID_ALL(5)


    .. attribute:: TCP_TABLE_OWNER_MODULE_LISTENER(6)


    .. attribute:: TCP_TABLE_OWNER_MODULE_CONNECTIONS(7)


    .. attribute:: TCP_TABLE_OWNER_MODULE_ALL(8)

_VARENUM
''''''''
.. class:: VARENUM

    Alias for :class:`_VARENUM`


.. class:: _VARENUM


    .. attribute:: VT_EMPTY(0)


    .. attribute:: VT_NULL(1)


    .. attribute:: VT_I2(2)


    .. attribute:: VT_I4(3)


    .. attribute:: VT_R4(4)


    .. attribute:: VT_R8(5)


    .. attribute:: VT_CY(6)


    .. attribute:: VT_DATE(7)


    .. attribute:: VT_BSTR(8)


    .. attribute:: VT_DISPATCH(9)


    .. attribute:: VT_ERROR(10)


    .. attribute:: VT_BOOL(11)


    .. attribute:: VT_VARIANT(12)


    .. attribute:: VT_UNKNOWN(13)


    .. attribute:: VT_DECIMAL(14)


    .. attribute:: VT_I1(16)


    .. attribute:: VT_UI1(17)


    .. attribute:: VT_UI2(18)


    .. attribute:: VT_UI4(19)


    .. attribute:: VT_I8(20)


    .. attribute:: VT_UI8(21)


    .. attribute:: VT_INT(22)


    .. attribute:: VT_UINT(23)


    .. attribute:: VT_VOID(24)


    .. attribute:: VT_HRESULT(25)


    .. attribute:: VT_PTR(26)


    .. attribute:: VT_SAFEARRAY(27)


    .. attribute:: VT_CARRAY(28)


    .. attribute:: VT_USERDEFINED(29)


    .. attribute:: VT_LPSTR(30)


    .. attribute:: VT_LPWSTR(31)


    .. attribute:: VT_RECORD(36)


    .. attribute:: VT_INT_PTR(37)


    .. attribute:: VT_UINT_PTR(38)


    .. attribute:: VT_FILETIME(64)


    .. attribute:: VT_BLOB(65)


    .. attribute:: VT_STREAM(66)


    .. attribute:: VT_STORAGE(67)


    .. attribute:: VT_STREAMED_OBJECT(68)


    .. attribute:: VT_STORED_OBJECT(69)


    .. attribute:: VT_BLOB_OBJECT(70)


    .. attribute:: VT_CF(71)


    .. attribute:: VT_CLSID(72)


    .. attribute:: VT_VERSIONED_STREAM(73)


    .. attribute:: VT_BSTR_BLOB(4095)


    .. attribute:: VT_VECTOR(4096)


    .. attribute:: VT_ARRAY(8192)


    .. attribute:: VT_BYREF(16384)


    .. attribute:: VT_RESERVED(32768)


    .. attribute:: VT_ILLEGAL(65535)


    .. attribute:: VT_ILLEGALMASKED(4095)


    .. attribute:: VT_TYPEMASK(4095)

_UDP_TABLE_CLASS
''''''''''''''''
.. class:: UDP_TABLE_CLASS

    Alias for :class:`_UDP_TABLE_CLASS`


.. class:: _UDP_TABLE_CLASS


    .. attribute:: UDP_TABLE_BASIC(0)


    .. attribute:: UDP_TABLE_OWNER_PID(1)


    .. attribute:: UDP_TABLE_OWNER_MODULE(2)

NET_FW_RULE_DIRECTION_
''''''''''''''''''''''
.. class:: NET_FW_RULE_DIRECTION

    Alias for :class:`NET_FW_RULE_DIRECTION_`


.. class:: NET_FW_RULE_DIRECTION_


    .. attribute:: NET_FW_RULE_DIR_IN(1)


    .. attribute:: NET_FW_RULE_DIR_OUT(2)


    .. attribute:: NET_FW_RULE_DIR_MAX(3)

NET_FW_PROFILE_TYPE2_
'''''''''''''''''''''
.. class:: NET_FW_PROFILE_TYPE2

    Alias for :class:`NET_FW_PROFILE_TYPE2_`


.. class:: NET_FW_PROFILE_TYPE2_


    .. attribute:: NET_FW_PROFILE2_DOMAIN(1)


    .. attribute:: NET_FW_PROFILE2_PRIVATE(2)


    .. attribute:: NET_FW_PROFILE2_PUBLIC(4)


    .. attribute:: NET_FW_PROFILE2_ALL(2147483647)

_MIB_TCP_STATE
''''''''''''''
.. class:: MIB_TCP_STATE

    Alias for :class:`_MIB_TCP_STATE`


.. class:: _MIB_TCP_STATE


    .. attribute:: MIB_TCP_STATE_CLOSED(1)


    .. attribute:: MIB_TCP_STATE_LISTEN(2)


    .. attribute:: MIB_TCP_STATE_SYN_SENT(3)


    .. attribute:: MIB_TCP_STATE_SYN_RCVD(4)


    .. attribute:: MIB_TCP_STATE_ESTAB(5)


    .. attribute:: MIB_TCP_STATE_FIN_WAIT1(6)


    .. attribute:: MIB_TCP_STATE_FIN_WAIT2(7)


    .. attribute:: MIB_TCP_STATE_CLOSE_WAIT(8)


    .. attribute:: MIB_TCP_STATE_CLOSING(9)


    .. attribute:: MIB_TCP_STATE_LAST_ACK(10)


    .. attribute:: MIB_TCP_STATE_TIME_WAIT(11)


    .. attribute:: MIB_TCP_STATE_DELETE_TCB(12)

NET_FW_IP_PROTOCOL_
'''''''''''''''''''
.. class:: NET_FW_IP_PROTOCOL

    Alias for :class:`NET_FW_IP_PROTOCOL_`


.. class:: NET_FW_IP_PROTOCOL_


    .. attribute:: NET_FW_IP_PROTOCOL_TCP(6)


    .. attribute:: NET_FW_IP_PROTOCOL_UDP(17)


    .. attribute:: NET_FW_IP_PROTOCOL_ANY(256)

_TOKEN_INFORMATION_CLASS
''''''''''''''''''''''''
.. class:: TOKEN_INFORMATION_CLASS

    Alias for :class:`_TOKEN_INFORMATION_CLASS`


.. class:: PTOKEN_INFORMATION_CLASS

    Pointer to :class:`_TOKEN_INFORMATION_CLASS`


.. class:: _TOKEN_INFORMATION_CLASS


    .. attribute:: TokenInvalid(0)


    .. attribute:: TokenUser(1)


    .. attribute:: TokenGroups(2)


    .. attribute:: TokenPrivileges(3)


    .. attribute:: TokenOwner(4)


    .. attribute:: TokenPrimaryGroup(5)


    .. attribute:: TokenDefaultDacl(6)


    .. attribute:: TokenSource(7)


    .. attribute:: TokenType(8)


    .. attribute:: TokenImpersonationLevel(9)


    .. attribute:: TokenStatistics(10)


    .. attribute:: TokenRestrictedSids(11)


    .. attribute:: TokenSessionId(12)


    .. attribute:: TokenGroupsAndPrivileges(13)


    .. attribute:: TokenSessionReference(14)


    .. attribute:: TokenSandBoxInert(15)


    .. attribute:: TokenAuditPolicy(16)


    .. attribute:: TokenOrigin(17)


    .. attribute:: TokenElevationType(18)


    .. attribute:: TokenLinkedToken(19)


    .. attribute:: TokenElevation(20)


    .. attribute:: TokenHasRestrictions(21)


    .. attribute:: TokenAccessInformation(22)


    .. attribute:: TokenVirtualizationAllowed(23)


    .. attribute:: TokenVirtualizationEnabled(24)


    .. attribute:: TokenIntegrityLevel(25)


    .. attribute:: TokenUIAccess(26)


    .. attribute:: TokenMandatoryPolicy(27)


    .. attribute:: TokenLogonSid(28)


    .. attribute:: TokenIsAppContainer(29)


    .. attribute:: TokenCapabilities(30)


    .. attribute:: TokenAppContainerSid(31)


    .. attribute:: TokenAppContainerNumber(32)


    .. attribute:: TokenUserClaimAttributes(33)


    .. attribute:: TokenDeviceClaimAttributes(34)


    .. attribute:: TokenRestrictedUserClaimAttributes(35)


    .. attribute:: TokenRestrictedDeviceClaimAttributes(36)


    .. attribute:: TokenDeviceGroups(37)


    .. attribute:: TokenRestrictedDeviceGroups(38)


    .. attribute:: TokenSecurityAttributes(39)


    .. attribute:: TokenIsRestricted(40)


    .. attribute:: MaxTokenInfoClass(41)

tagTOKEN_TYPE
'''''''''''''
.. class:: TOKEN_TYPE

    Alias for :class:`tagTOKEN_TYPE`


.. class:: PTOKEN_TYPE

    Pointer to :class:`tagTOKEN_TYPE`


.. class:: tagTOKEN_TYPE


    .. attribute:: TokenPrimary(1)


    .. attribute:: TokenImpersonation(2)

_FS_INFORMATION_CLASS
'''''''''''''''''''''
.. class:: FS_INFORMATION_CLASS

    Alias for :class:`_FS_INFORMATION_CLASS`


.. class:: _FS_INFORMATION_CLASS


    .. attribute:: FileFsVolumeInformation(1)


    .. attribute:: FileFsLabelInformation(2)


    .. attribute:: FileFsSizeInformation(3)


    .. attribute:: FileFsDeviceInformation(4)


    .. attribute:: FileFsAttributeInformation(5)


    .. attribute:: FileFsControlInformation(6)


    .. attribute:: FileFsFullSizeInformation(7)


    .. attribute:: FileFsObjectIdInformation(8)


    .. attribute:: FileFsDriverPathInformation(9)


    .. attribute:: FileFsVolumeFlagsInformation(10)


    .. attribute:: FileFsSectorSizeInformation(11)

_SECURITY_IMPERSONATION_LEVEL
'''''''''''''''''''''''''''''
.. class:: SECURITY_IMPERSONATION_LEVEL

    Alias for :class:`_SECURITY_IMPERSONATION_LEVEL`


.. class:: PSECURITY_IMPERSONATION_LEVEL

    Pointer to :class:`_SECURITY_IMPERSONATION_LEVEL`


.. class:: _SECURITY_IMPERSONATION_LEVEL


    .. attribute:: SecurityAnonymous(0)


    .. attribute:: SecurityIdentification(1)


    .. attribute:: SecurityImpersonation(2)


    .. attribute:: SecurityDelegation(3)

_SC_ENUM_TYPE
'''''''''''''
.. class:: SC_ENUM_TYPE

    Alias for :class:`_SC_ENUM_TYPE`


.. class:: _SC_ENUM_TYPE


    .. attribute:: SC_ENUM_PROCESS_INFO(0)

_SC_STATUS_TYPE
'''''''''''''''
.. class:: SC_STATUS_TYPE

    Alias for :class:`_SC_STATUS_TYPE`


.. class:: _SC_STATUS_TYPE


    .. attribute:: SC_STATUS_PROCESS_INFO(0)

_OBJECT_INFORMATION_CLASS
'''''''''''''''''''''''''
.. class:: OBJECT_INFORMATION_CLASS

    Alias for :class:`_OBJECT_INFORMATION_CLASS`


.. class:: _OBJECT_INFORMATION_CLASS


    .. attribute:: ObjectBasicInformation(0)


    .. attribute:: ObjectNameInformation(1)


    .. attribute:: ObjectTypeInformation(2)

_SID_NAME_USE
'''''''''''''
.. class:: SID_NAME_USE

    Alias for :class:`_SID_NAME_USE`


.. class:: PSID_NAME_USE

    Pointer to :class:`_SID_NAME_USE`


.. class:: _SID_NAME_USE


    .. attribute:: SidTypeUser(1)


    .. attribute:: SidTypeGroup(2)


    .. attribute:: SidTypeDomain(3)


    .. attribute:: SidTypeAlias(4)


    .. attribute:: SidTypeWellKnownGroup(5)


    .. attribute:: SidTypeDeletedAccount(6)


    .. attribute:: SidTypeInvalid(7)


    .. attribute:: SidTypeUnknown(8)


    .. attribute:: SidTypeComputer(9)


    .. attribute:: SidTypeLabel(10)

NET_FW_ACTION_
''''''''''''''
.. class:: NET_FW_ACTION

    Alias for :class:`NET_FW_ACTION_`


.. class:: NET_FW_ACTION_


    .. attribute:: NET_FW_ACTION_BLOCK(0)


    .. attribute:: NET_FW_ACTION_ALLOW(1)


    .. attribute:: NET_FW_ACTION_MAX(2)

NET_FW_MODIFY_STATE_
''''''''''''''''''''
.. class:: NET_FW_MODIFY_STATE

    Alias for :class:`NET_FW_MODIFY_STATE_`


.. class:: NET_FW_MODIFY_STATE_


    .. attribute:: NET_FW_MODIFY_STATE_OK(0)


    .. attribute:: NET_FW_MODIFY_STATE_GP_OVERRIDE(1)


    .. attribute:: NET_FW_MODIFY_STATE_INBOUND_BLOCKED(2)

tag_WBEMSTATUS
''''''''''''''
.. class:: WBEMSTATUS

    Alias for :class:`tag_WBEMSTATUS`


.. class:: tag_WBEMSTATUS


    .. attribute:: WBEM_NO_ERROR(0)


    .. attribute:: WBEM_S_NO_ERROR(0)


    .. attribute:: WBEM_S_SAME(0)


    .. attribute:: WBEM_S_FALSE(1)


    .. attribute:: WBEM_S_ALREADY_EXISTS(262145)


    .. attribute:: WBEM_S_RESET_TO_DEFAULT(262146)


    .. attribute:: WBEM_S_DIFFERENT(262147)


    .. attribute:: WBEM_S_TIMEDOUT(262148)


    .. attribute:: WBEM_S_NO_MORE_DATA(262149)


    .. attribute:: WBEM_S_OPERATION_CANCELLED(262150)


    .. attribute:: WBEM_S_PENDING(262151)


    .. attribute:: WBEM_S_DUPLICATE_OBJECTS(262152)


    .. attribute:: WBEM_S_ACCESS_DENIED(262153)


    .. attribute:: WBEM_S_PARTIAL_RESULTS(262160)


    .. attribute:: WBEM_S_SOURCE_NOT_AVAILABLE(262167)


    .. attribute:: WBEM_E_FAILED(2147749889)


    .. attribute:: WBEM_E_NOT_FOUND(2147749890)


    .. attribute:: WBEM_E_ACCESS_DENIED(2147749891)


    .. attribute:: WBEM_E_PROVIDER_FAILURE(2147749892)


    .. attribute:: WBEM_E_TYPE_MISMATCH(2147749893)


    .. attribute:: WBEM_E_OUT_OF_MEMORY(2147749894)


    .. attribute:: WBEM_E_INVALID_CONTEXT(2147749895)


    .. attribute:: WBEM_E_INVALID_PARAMETER(2147749896)


    .. attribute:: WBEM_E_NOT_AVAILABLE(2147749897)


    .. attribute:: WBEM_E_CRITICAL_ERROR(2147749898)


    .. attribute:: WBEM_E_INVALID_STREAM(2147749899)


    .. attribute:: WBEM_E_NOT_SUPPORTED(2147749900)


    .. attribute:: WBEM_E_INVALID_SUPERCLASS(2147749901)


    .. attribute:: WBEM_E_INVALID_NAMESPACE(2147749902)


    .. attribute:: WBEM_E_INVALID_OBJECT(2147749903)


    .. attribute:: WBEM_E_INVALID_CLASS(2147749904)


    .. attribute:: WBEM_E_PROVIDER_NOT_FOUND(2147749905)


    .. attribute:: WBEM_E_INVALID_PROVIDER_REGISTRATION(2147749906)


    .. attribute:: WBEM_E_PROVIDER_LOAD_FAILURE(2147749907)


    .. attribute:: WBEM_E_INITIALIZATION_FAILURE(2147749908)


    .. attribute:: WBEM_E_TRANSPORT_FAILURE(2147749909)


    .. attribute:: WBEM_E_INVALID_OPERATION(2147749910)


    .. attribute:: WBEM_E_INVALID_QUERY(2147749911)


    .. attribute:: WBEM_E_INVALID_QUERY_TYPE(2147749912)


    .. attribute:: WBEM_E_ALREADY_EXISTS(2147749913)


    .. attribute:: WBEM_E_OVERRIDE_NOT_ALLOWED(2147749914)


    .. attribute:: WBEM_E_PROPAGATED_QUALIFIER(2147749915)


    .. attribute:: WBEM_E_PROPAGATED_PROPERTY(2147749916)


    .. attribute:: WBEM_E_UNEXPECTED(2147749917)


    .. attribute:: WBEM_E_ILLEGAL_OPERATION(2147749918)


    .. attribute:: WBEM_E_CANNOT_BE_KEY(2147749919)


    .. attribute:: WBEM_E_INCOMPLETE_CLASS(2147749920)


    .. attribute:: WBEM_E_INVALID_SYNTAX(2147749921)


    .. attribute:: WBEM_E_NONDECORATED_OBJECT(2147749922)


    .. attribute:: WBEM_E_READ_ONLY(2147749923)


    .. attribute:: WBEM_E_PROVIDER_NOT_CAPABLE(2147749924)


    .. attribute:: WBEM_E_CLASS_HAS_CHILDREN(2147749925)


    .. attribute:: WBEM_E_CLASS_HAS_INSTANCES(2147749926)


    .. attribute:: WBEM_E_QUERY_NOT_IMPLEMENTED(2147749927)


    .. attribute:: WBEM_E_ILLEGAL_NULL(2147749928)


    .. attribute:: WBEM_E_INVALID_QUALIFIER_TYPE(2147749929)


    .. attribute:: WBEM_E_INVALID_PROPERTY_TYPE(2147749930)


    .. attribute:: WBEM_E_VALUE_OUT_OF_RANGE(2147749931)


    .. attribute:: WBEM_E_CANNOT_BE_SINGLETON(2147749932)


    .. attribute:: WBEM_E_INVALID_CIM_TYPE(2147749933)


    .. attribute:: WBEM_E_INVALID_METHOD(2147749934)


    .. attribute:: WBEM_E_INVALID_METHOD_PARAMETERS(2147749935)


    .. attribute:: WBEM_E_SYSTEM_PROPERTY(2147749936)


    .. attribute:: WBEM_E_INVALID_PROPERTY(2147749937)


    .. attribute:: WBEM_E_CALL_CANCELLED(2147749938)


    .. attribute:: WBEM_E_SHUTTING_DOWN(2147749939)


    .. attribute:: WBEM_E_PROPAGATED_METHOD(2147749940)


    .. attribute:: WBEM_E_UNSUPPORTED_PARAMETER(2147749941)


    .. attribute:: WBEM_E_MISSING_PARAMETER_ID(2147749942)


    .. attribute:: WBEM_E_INVALID_PARAMETER_ID(2147749943)


    .. attribute:: WBEM_E_NONCONSECUTIVE_PARAMETER_IDS(2147749944)


    .. attribute:: WBEM_E_PARAMETER_ID_ON_RETVAL(2147749945)


    .. attribute:: WBEM_E_INVALID_OBJECT_PATH(2147749946)


    .. attribute:: WBEM_E_OUT_OF_DISK_SPACE(2147749947)


    .. attribute:: WBEM_E_BUFFER_TOO_SMALL(2147749948)


    .. attribute:: WBEM_E_UNSUPPORTED_PUT_EXTENSION(2147749949)


    .. attribute:: WBEM_E_UNKNOWN_OBJECT_TYPE(2147749950)


    .. attribute:: WBEM_E_UNKNOWN_PACKET_TYPE(2147749951)


    .. attribute:: WBEM_E_MARSHAL_VERSION_MISMATCH(2147749952)


    .. attribute:: WBEM_E_MARSHAL_INVALID_SIGNATURE(2147749953)


    .. attribute:: WBEM_E_INVALID_QUALIFIER(2147749954)


    .. attribute:: WBEM_E_INVALID_DUPLICATE_PARAMETER(2147749955)


    .. attribute:: WBEM_E_TOO_MUCH_DATA(2147749956)


    .. attribute:: WBEM_E_SERVER_TOO_BUSY(2147749957)


    .. attribute:: WBEM_E_INVALID_FLAVOR(2147749958)


    .. attribute:: WBEM_E_CIRCULAR_REFERENCE(2147749959)


    .. attribute:: WBEM_E_UNSUPPORTED_CLASS_UPDATE(2147749960)


    .. attribute:: WBEM_E_CANNOT_CHANGE_KEY_INHERITANCE(2147749961)


    .. attribute:: WBEM_E_CANNOT_CHANGE_INDEX_INHERITANCE(2147749968)


    .. attribute:: WBEM_E_TOO_MANY_PROPERTIES(2147749969)


    .. attribute:: WBEM_E_UPDATE_TYPE_MISMATCH(2147749970)


    .. attribute:: WBEM_E_UPDATE_OVERRIDE_NOT_ALLOWED(2147749971)


    .. attribute:: WBEM_E_UPDATE_PROPAGATED_METHOD(2147749972)


    .. attribute:: WBEM_E_METHOD_NOT_IMPLEMENTED(2147749973)


    .. attribute:: WBEM_E_METHOD_DISABLED(2147749974)


    .. attribute:: WBEM_E_REFRESHER_BUSY(2147749975)


    .. attribute:: WBEM_E_UNPARSABLE_QUERY(2147749976)


    .. attribute:: WBEM_E_NOT_EVENT_CLASS(2147749977)


    .. attribute:: WBEM_E_MISSING_GROUP_WITHIN(2147749978)


    .. attribute:: WBEM_E_MISSING_AGGREGATION_LIST(2147749979)


    .. attribute:: WBEM_E_PROPERTY_NOT_AN_OBJECT(2147749980)


    .. attribute:: WBEM_E_AGGREGATING_BY_OBJECT(2147749981)


    .. attribute:: WBEM_E_UNINTERPRETABLE_PROVIDER_QUERY(2147749983)


    .. attribute:: WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING(2147749984)


    .. attribute:: WBEM_E_QUEUE_OVERFLOW(2147749985)


    .. attribute:: WBEM_E_PRIVILEGE_NOT_HELD(2147749986)


    .. attribute:: WBEM_E_INVALID_OPERATOR(2147749987)


    .. attribute:: WBEM_E_LOCAL_CREDENTIALS(2147749988)


    .. attribute:: WBEM_E_CANNOT_BE_ABSTRACT(2147749989)


    .. attribute:: WBEM_E_AMENDED_OBJECT(2147749990)


    .. attribute:: WBEM_E_CLIENT_TOO_SLOW(2147749991)


    .. attribute:: WBEM_E_NULL_SECURITY_DESCRIPTOR(2147749992)


    .. attribute:: WBEM_E_TIMED_OUT(2147749993)


    .. attribute:: WBEM_E_INVALID_ASSOCIATION(2147749994)


    .. attribute:: WBEM_E_AMBIGUOUS_OPERATION(2147749995)


    .. attribute:: WBEM_E_QUOTA_VIOLATION(2147749996)


    .. attribute:: WBEM_E_RESERVED_001(2147749997)


    .. attribute:: WBEM_E_RESERVED_002(2147749998)


    .. attribute:: WBEM_E_UNSUPPORTED_LOCALE(2147749999)


    .. attribute:: WBEM_E_HANDLE_OUT_OF_DATE(2147750000)


    .. attribute:: WBEM_E_CONNECTION_FAILED(2147750001)


    .. attribute:: WBEM_E_INVALID_HANDLE_REQUEST(2147750002)


    .. attribute:: WBEM_E_PROPERTY_NAME_TOO_WIDE(2147750003)


    .. attribute:: WBEM_E_CLASS_NAME_TOO_WIDE(2147750004)


    .. attribute:: WBEM_E_METHOD_NAME_TOO_WIDE(2147750005)


    .. attribute:: WBEM_E_QUALIFIER_NAME_TOO_WIDE(2147750006)


    .. attribute:: WBEM_E_RERUN_COMMAND(2147750007)


    .. attribute:: WBEM_E_DATABASE_VER_MISMATCH(2147750008)


    .. attribute:: WBEM_E_VETO_DELETE(2147750009)


    .. attribute:: WBEM_E_VETO_PUT(2147750010)


    .. attribute:: WBEM_E_INVALID_LOCALE(2147750016)


    .. attribute:: WBEM_E_PROVIDER_SUSPENDED(2147750017)


    .. attribute:: WBEM_E_SYNCHRONIZATION_REQUIRED(2147750018)


    .. attribute:: WBEM_E_NO_SCHEMA(2147750019)


    .. attribute:: WBEM_E_PROVIDER_ALREADY_REGISTERED(2147750020)


    .. attribute:: WBEM_E_PROVIDER_NOT_REGISTERED(2147750021)


    .. attribute:: WBEM_E_FATAL_TRANSPORT_ERROR(2147750022)


    .. attribute:: WBEM_E_ENCRYPTED_CONNECTION_REQUIRED(2147750023)


    .. attribute:: WBEM_E_PROVIDER_TIMED_OUT(2147750024)


    .. attribute:: WBEM_E_NO_KEY(2147750025)


    .. attribute:: WBEM_E_PROVIDER_DISABLED(2147750026)


    .. attribute:: WBEMESS_E_REGISTRATION_TOO_BROAD(2147753985)


    .. attribute:: WBEMESS_E_REGISTRATION_TOO_PRECISE(2147753986)


    .. attribute:: WBEMESS_E_AUTHZ_NOT_PRIVILEGED(2147753987)


    .. attribute:: WBEMMOF_E_EXPECTED_QUALIFIER_NAME(2147762177)


    .. attribute:: WBEMMOF_E_EXPECTED_SEMI(2147762178)


    .. attribute:: WBEMMOF_E_EXPECTED_OPEN_BRACE(2147762179)


    .. attribute:: WBEMMOF_E_EXPECTED_CLOSE_BRACE(2147762180)


    .. attribute:: WBEMMOF_E_EXPECTED_CLOSE_BRACKET(2147762181)


    .. attribute:: WBEMMOF_E_EXPECTED_CLOSE_PAREN(2147762182)


    .. attribute:: WBEMMOF_E_ILLEGAL_CONSTANT_VALUE(2147762183)


    .. attribute:: WBEMMOF_E_EXPECTED_TYPE_IDENTIFIER(2147762184)


    .. attribute:: WBEMMOF_E_EXPECTED_OPEN_PAREN(2147762185)


    .. attribute:: WBEMMOF_E_UNRECOGNIZED_TOKEN(2147762186)


    .. attribute:: WBEMMOF_E_UNRECOGNIZED_TYPE(2147762187)


    .. attribute:: WBEMMOF_E_EXPECTED_PROPERTY_NAME(2147762188)


    .. attribute:: WBEMMOF_E_TYPEDEF_NOT_SUPPORTED(2147762189)


    .. attribute:: WBEMMOF_E_UNEXPECTED_ALIAS(2147762190)


    .. attribute:: WBEMMOF_E_UNEXPECTED_ARRAY_INIT(2147762191)


    .. attribute:: WBEMMOF_E_INVALID_AMENDMENT_SYNTAX(2147762192)


    .. attribute:: WBEMMOF_E_INVALID_DUPLICATE_AMENDMENT(2147762193)


    .. attribute:: WBEMMOF_E_INVALID_PRAGMA(2147762194)


    .. attribute:: WBEMMOF_E_INVALID_NAMESPACE_SYNTAX(2147762195)


    .. attribute:: WBEMMOF_E_EXPECTED_CLASS_NAME(2147762196)


    .. attribute:: WBEMMOF_E_TYPE_MISMATCH(2147762197)


    .. attribute:: WBEMMOF_E_EXPECTED_ALIAS_NAME(2147762198)


    .. attribute:: WBEMMOF_E_INVALID_CLASS_DECLARATION(2147762199)


    .. attribute:: WBEMMOF_E_INVALID_INSTANCE_DECLARATION(2147762200)


    .. attribute:: WBEMMOF_E_EXPECTED_DOLLAR(2147762201)


    .. attribute:: WBEMMOF_E_CIMTYPE_QUALIFIER(2147762202)


    .. attribute:: WBEMMOF_E_DUPLICATE_PROPERTY(2147762203)


    .. attribute:: WBEMMOF_E_INVALID_NAMESPACE_SPECIFICATION(2147762204)


    .. attribute:: WBEMMOF_E_OUT_OF_RANGE(2147762205)


    .. attribute:: WBEMMOF_E_INVALID_FILE(2147762206)


    .. attribute:: WBEMMOF_E_ALIASES_IN_EMBEDDED(2147762207)


    .. attribute:: WBEMMOF_E_NULL_ARRAY_ELEM(2147762208)


    .. attribute:: WBEMMOF_E_DUPLICATE_QUALIFIER(2147762209)


    .. attribute:: WBEMMOF_E_EXPECTED_FLAVOR_TYPE(2147762210)


    .. attribute:: WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES(2147762211)


    .. attribute:: WBEMMOF_E_MULTIPLE_ALIASES(2147762212)


    .. attribute:: WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES2(2147762213)


    .. attribute:: WBEMMOF_E_NO_ARRAYS_RETURNED(2147762214)


    .. attribute:: WBEMMOF_E_MUST_BE_IN_OR_OUT(2147762215)


    .. attribute:: WBEMMOF_E_INVALID_FLAGS_SYNTAX(2147762216)


    .. attribute:: WBEMMOF_E_EXPECTED_BRACE_OR_BAD_TYPE(2147762217)


    .. attribute:: WBEMMOF_E_UNSUPPORTED_CIMV22_QUAL_VALUE(2147762218)


    .. attribute:: WBEMMOF_E_UNSUPPORTED_CIMV22_DATA_TYPE(2147762219)


    .. attribute:: WBEMMOF_E_INVALID_DELETEINSTANCE_SYNTAX(2147762220)


    .. attribute:: WBEMMOF_E_INVALID_QUALIFIER_SYNTAX(2147762221)


    .. attribute:: WBEMMOF_E_QUALIFIER_USED_OUTSIDE_SCOPE(2147762222)


    .. attribute:: WBEMMOF_E_ERROR_CREATING_TEMP_FILE(2147762223)


    .. attribute:: WBEMMOF_E_ERROR_INVALID_INCLUDE_FILE(2147762224)


    .. attribute:: WBEMMOF_E_INVALID_DELETECLASS_SYNTAX(2147762225)

tag_WBEM_CHANGE_FLAG_TYPE
'''''''''''''''''''''''''
.. class:: WBEM_CHANGE_FLAG_TYPE

    Alias for :class:`tag_WBEM_CHANGE_FLAG_TYPE`


.. class:: tag_WBEM_CHANGE_FLAG_TYPE


    .. attribute:: WBEM_FLAG_CREATE_OR_UPDATE(0)


    .. attribute:: WBEM_FLAG_UPDATE_ONLY(1)


    .. attribute:: WBEM_FLAG_CREATE_ONLY(2)


    .. attribute:: WBEM_FLAG_UPDATE_COMPATIBLE(0)


    .. attribute:: WBEM_FLAG_UPDATE_SAFE_MODE(32)


    .. attribute:: WBEM_FLAG_UPDATE_FORCE_MODE(64)


    .. attribute:: WBEM_MASK_UPDATE_MODE(96)


    .. attribute:: WBEM_FLAG_ADVISORY(65536)

tag_WBEM_TIMEOUT_TYPE
'''''''''''''''''''''
.. class:: WBEM_TIMEOUT_TYPE

    Alias for :class:`tag_WBEM_TIMEOUT_TYPE`


.. class:: tag_WBEM_TIMEOUT_TYPE


    .. attribute:: WBEM_NO_WAIT(0)


    .. attribute:: WBEM_INFINITE(4294967295)

tag_WBEM_GENERIC_FLAG_TYPE
''''''''''''''''''''''''''
.. class:: WBEM_GENERIC_FLAG_TYPE

    Alias for :class:`tag_WBEM_GENERIC_FLAG_TYPE`


.. class:: tag_WBEM_GENERIC_FLAG_TYPE


    .. attribute:: WBEM_FLAG_RETURN_IMMEDIATELY(16)


    .. attribute:: WBEM_FLAG_RETURN_WBEM_COMPLETE(0)


    .. attribute:: WBEM_FLAG_BIDIRECTIONAL(0)


    .. attribute:: WBEM_FLAG_FORWARD_ONLY(32)


    .. attribute:: WBEM_FLAG_NO_ERROR_OBJECT(64)


    .. attribute:: WBEM_FLAG_RETURN_ERROR_OBJECT(0)


    .. attribute:: WBEM_FLAG_SEND_STATUS(128)


    .. attribute:: WBEM_FLAG_DONT_SEND_STATUS(0)


    .. attribute:: WBEM_FLAG_ENSURE_LOCATABLE(256)


    .. attribute:: WBEM_FLAG_DIRECT_READ(512)


    .. attribute:: WBEM_FLAG_SEND_ONLY_SELECTED(0)


    .. attribute:: WBEM_RETURN_WHEN_COMPLETE(0)


    .. attribute:: WBEM_RETURN_IMMEDIATELY(16)


    .. attribute:: WBEM_MASK_RESERVED_FLAGS(126976)


    .. attribute:: WBEM_FLAG_USE_AMENDED_QUALIFIERS(131072)


    .. attribute:: WBEM_FLAG_STRONG_VALIDATION(1048576)

tagCLSCTX
'''''''''
.. class:: CLSCTX

    Alias for :class:`tagCLSCTX`


.. class:: tagCLSCTX


    .. attribute:: CLSCTX_INPROC_SERVER(1)


    .. attribute:: CLSCTX_INPROC_HANDLER(2)


    .. attribute:: CLSCTX_LOCAL_SERVER(4)


    .. attribute:: CLSCTX_INPROC_SERVER16(8)


    .. attribute:: CLSCTX_REMOTE_SERVER(16)


    .. attribute:: CLSCTX_INPROC_HANDLER16(32)


    .. attribute:: CLSCTX_RESERVED1(64)


    .. attribute:: CLSCTX_RESERVED2(128)


    .. attribute:: CLSCTX_RESERVED3(256)


    .. attribute:: CLSCTX_RESERVED4(512)


    .. attribute:: CLSCTX_NO_CODE_DOWNLOAD(1024)


    .. attribute:: CLSCTX_RESERVED5(2048)


    .. attribute:: CLSCTX_NO_CUSTOM_MARSHAL(4096)


    .. attribute:: CLSCTX_ENABLE_CODE_DOWNLOAD(8192)


    .. attribute:: CLSCTX_NO_FAILURE_LOG(16384)


    .. attribute:: CLSCTX_DISABLE_AAA(32768)


    .. attribute:: CLSCTX_ENABLE_AAA(65536)


    .. attribute:: CLSCTX_FROM_DEFAULT_CONTEXT(131072)


    .. attribute:: CLSCTX_ACTIVATE_32_BIT_SERVER(262144)


    .. attribute:: CLSCTX_ACTIVATE_64_BIT_SERVER(524288)


    .. attribute:: CLSCTX_ENABLE_CLOAKING(1048576)


    .. attribute:: CLSCTX_APPCONTAINER(4194304)


    .. attribute:: CLSCTX_ACTIVATE_AAA_AS_IU(8388608)


    .. attribute:: CLSCTX_PS_DLL(2147483648)

_SE_OBJECT_TYPE
'''''''''''''''
.. class:: SE_OBJECT_TYPE

    Alias for :class:`_SE_OBJECT_TYPE`


.. class:: _SE_OBJECT_TYPE


    .. attribute:: SE_UNKNOWN_OBJECT_TYPE(0)


    .. attribute:: SE_FILE_OBJECT(1)


    .. attribute:: SE_SERVICE(2)


    .. attribute:: SE_PRINTER(3)


    .. attribute:: SE_REGISTRY_KEY(4)


    .. attribute:: SE_LMSHARE(5)


    .. attribute:: SE_KERNEL_OBJECT(6)


    .. attribute:: SE_WINDOW_OBJECT(7)


    .. attribute:: SE_DS_OBJECT(8)


    .. attribute:: SE_DS_OBJECT_ALL(9)


    .. attribute:: SE_PROVIDER_DEFINED_OBJECT(10)


    .. attribute:: SE_WMIGUID_OBJECT(11)


    .. attribute:: SE_REGISTRY_WOW64_32KEY(12)

_INTERNAL_IF_OPER_STATUS
''''''''''''''''''''''''
.. class:: INTERNAL_IF_OPER_STATUS

    Alias for :class:`_INTERNAL_IF_OPER_STATUS`


.. class:: _INTERNAL_IF_OPER_STATUS


    .. attribute:: IF_OPER_STATUS_NON_OPERATIONAL(0)


    .. attribute:: IF_OPER_STATUS_UNREACHABLE(1)


    .. attribute:: IF_OPER_STATUS_DISCONNECTED(2)


    .. attribute:: IF_OPER_STATUS_CONNECTING(3)


    .. attribute:: IF_OPER_STATUS_CONNECTED(4)


    .. attribute:: IF_OPER_STATUS_OPERATIONAL(5)

_IMAGEHLP_SYMBOL_TYPE_INFO
''''''''''''''''''''''''''
.. class:: IMAGEHLP_SYMBOL_TYPE_INFO

    Alias for :class:`_IMAGEHLP_SYMBOL_TYPE_INFO`


.. class:: _IMAGEHLP_SYMBOL_TYPE_INFO


    .. attribute:: TI_GET_SYMTAG(0)


    .. attribute:: TI_GET_SYMNAME(1)


    .. attribute:: TI_GET_LENGTH(2)


    .. attribute:: TI_GET_TYPE(3)


    .. attribute:: TI_GET_TYPEID(4)


    .. attribute:: TI_GET_BASETYPE(5)


    .. attribute:: TI_GET_ARRAYINDEXTYPEID(6)


    .. attribute:: TI_FINDCHILDREN(7)


    .. attribute:: TI_GET_DATAKIND(8)


    .. attribute:: TI_GET_ADDRESSOFFSET(9)


    .. attribute:: TI_GET_OFFSET(10)


    .. attribute:: TI_GET_VALUE(11)


    .. attribute:: TI_GET_COUNT(12)


    .. attribute:: TI_GET_CHILDRENCOUNT(13)


    .. attribute:: TI_GET_BITPOSITION(14)


    .. attribute:: TI_GET_VIRTUALBASECLASS(15)


    .. attribute:: TI_GET_VIRTUALTABLESHAPEID(16)


    .. attribute:: TI_GET_VIRTUALBASEPOINTEROFFSET(17)


    .. attribute:: TI_GET_CLASSPARENTID(18)


    .. attribute:: TI_GET_NESTED(19)


    .. attribute:: TI_GET_SYMINDEX(20)


    .. attribute:: TI_GET_LEXICALPARENT(21)


    .. attribute:: TI_GET_ADDRESS(22)


    .. attribute:: TI_GET_THISADJUST(23)


    .. attribute:: TI_GET_UDTKIND(24)


    .. attribute:: TI_IS_EQUIV_TO(25)


    .. attribute:: TI_GET_CALLING_CONVENTION(26)


    .. attribute:: TI_IS_CLOSE_EQUIV_TO(27)


    .. attribute:: TI_GTIEX_REQS_VALID(28)


    .. attribute:: TI_GET_VIRTUALBASEOFFSET(29)


    .. attribute:: TI_GET_VIRTUALBASEDISPINDEX(30)


    .. attribute:: TI_GET_IS_REFERENCE(31)


    .. attribute:: TI_GET_INDIRECTVIRTUALBASECLASS(32)


    .. attribute:: IMAGEHLP_SYMBOL_TYPE_INFO_MAX(33)

_PROCESSINFOCLASS
'''''''''''''''''
.. class:: PROCESSINFOCLASS

    Alias for :class:`_PROCESSINFOCLASS`


.. class:: _PROCESSINFOCLASS


    .. attribute:: ProcessBasicInformation(0)


    .. attribute:: ProcessWow64Information(26)

tagCOINIT
'''''''''
.. class:: COINIT

    Alias for :class:`tagCOINIT`


.. class:: tagCOINIT


    .. attribute:: COINIT_APARTMENTTHREADED(2)


    .. attribute:: COINIT_MULTITHREADED(0)


    .. attribute:: COINIT_DISABLE_OLE1DDE(4)


    .. attribute:: COINIT_SPEED_OVER_MEMORY(8)

tagTYPEKIND
'''''''''''
.. class:: TYPEKIND

    Alias for :class:`tagTYPEKIND`


.. class:: tagTYPEKIND


    .. attribute:: TKIND_ENUM(0)


    .. attribute:: TKIND_RECORD(1)


    .. attribute:: TKIND_MODULE(2)


    .. attribute:: TKIND_INTERFACE(3)


    .. attribute:: TKIND_DISPATCH(4)


    .. attribute:: TKIND_COCLASS(5)


    .. attribute:: TKIND_ALIAS(6)


    .. attribute:: TKIND_UNION(7)


    .. attribute:: TKIND_MAX(8)

_RTL_PATH_TYPE
''''''''''''''
.. class:: RTL_PATH_TYPE

    Alias for :class:`_RTL_PATH_TYPE`


.. class:: _RTL_PATH_TYPE


    .. attribute:: RtlPathTypeUnknown(0)


    .. attribute:: RtlPathTypeUncAbsolute(1)


    .. attribute:: RtlPathTypeDriveAbsolute(2)


    .. attribute:: RtlPathTypeDriveRelative(3)


    .. attribute:: RtlPathTypeRooted(4)


    .. attribute:: RtlPathTypeRelative(5)


    .. attribute:: RtlPathTypeLocalDevice(6)


    .. attribute:: RtlPathTypeRootLocalDevice(7)

_ALPC_PORT_INFORMATION_CLASS
''''''''''''''''''''''''''''
.. class:: ALPC_PORT_INFORMATION_CLASS

    Alias for :class:`_ALPC_PORT_INFORMATION_CLASS`


.. class:: _ALPC_PORT_INFORMATION_CLASS


    .. attribute:: AlpcBasicInformation(0)


    .. attribute:: AlpcPortInformation(1)


    .. attribute:: AlpcAssociateCompletionPortInformation(2)


    .. attribute:: AlpcConnectedSIDInformation(3)


    .. attribute:: AlpcServerInformation(4)


    .. attribute:: AlpcMessageZoneInformation(5)


    .. attribute:: AlpcRegisterCompletionListInformation(6)


    .. attribute:: AlpcUnregisterCompletionListInformation(7)


    .. attribute:: AlpcAdjustCompletionListConcurrencyCountInformation(8)


    .. attribute:: AlpcRegisterCallbackInformation(9)


    .. attribute:: AlpcCompletionListRundownInformation(10)


    .. attribute:: AlpcWaitForPortReferences(11)


    .. attribute:: MaxAlpcPortInfoClass(12)

_ALPC_MESSAGE_INFORMATION_CLASS
'''''''''''''''''''''''''''''''
.. class:: ALPC_MESSAGE_INFORMATION_CLASS

    Alias for :class:`_ALPC_MESSAGE_INFORMATION_CLASS`


.. class:: PALPC_MESSAGE_INFORMATION_CLASS

    Pointer to :class:`_ALPC_MESSAGE_INFORMATION_CLASS`


.. class:: _ALPC_MESSAGE_INFORMATION_CLASS


    .. attribute:: AlpcMessageSidInformation(0)


    .. attribute:: AlpcMessageTokenModifiedIdInformation(1)


    .. attribute:: MaxAlpcMessageInfoClass(2)


    .. attribute:: AlpcMessageHandleInformation(3)

_BG_JOB_STATE
'''''''''''''
.. class:: BG_JOB_STATE

    Alias for :class:`_BG_JOB_STATE`


.. class:: _BG_JOB_STATE


    .. attribute:: BG_JOB_STATE_QUEUED(0)


    .. attribute:: BG_JOB_STATE_CONNECTING(1)


    .. attribute:: BG_JOB_STATE_TRANSFERRING(2)


    .. attribute:: BG_JOB_STATE_SUSPENDED(3)


    .. attribute:: BG_JOB_STATE_ERROR(4)


    .. attribute:: BG_JOB_STATE_TRANSIENT_ERROR(5)


    .. attribute:: BG_JOB_STATE_TRANSFERRED(6)


    .. attribute:: BG_JOB_STATE_ACKNOWLEDGED(7)


    .. attribute:: BG_JOB_STATE_CANCELLED(8)

_BG_JOB_PROXY_USAGE
'''''''''''''''''''
.. class:: BG_JOB_PROXY_USAGE

    Alias for :class:`_BG_JOB_PROXY_USAGE`


.. class:: _BG_JOB_PROXY_USAGE


    .. attribute:: BG_JOB_PROXY_USAGE_PRECONFIG(0)


    .. attribute:: BG_JOB_PROXY_USAGE_NO_PROXY(1)


    .. attribute:: BG_JOB_PROXY_USAGE_OVERRIDE(2)


    .. attribute:: BG_JOB_PROXY_USAGE_AUTODETECT(3)

_BG_JOB_PRIORITY
''''''''''''''''
.. class:: BG_JOB_PRIORITY

    Alias for :class:`_BG_JOB_PRIORITY`


.. class:: _BG_JOB_PRIORITY


    .. attribute:: BG_JOB_PRIORITY_FOREGROUND(0)


    .. attribute:: BG_JOB_PRIORITY_HIGH(1)


    .. attribute:: BG_JOB_PRIORITY_NORMAL(2)


    .. attribute:: BG_JOB_PRIORITY_LOW(3)

_BG_ERROR_CONTEXT
'''''''''''''''''
.. class:: BG_ERROR_CONTEXT

    Alias for :class:`_BG_ERROR_CONTEXT`


.. class:: _BG_ERROR_CONTEXT


    .. attribute:: BG_ERROR_CONTEXT_NONE(0)


    .. attribute:: BG_ERROR_CONTEXT_UNKNOWN(1)


    .. attribute:: BG_ERROR_CONTEXT_GENERAL_QUEUE_MANAGER(2)


    .. attribute:: BG_ERROR_CONTEXT_QUEUE_MANAGER_NOTIFICATION(3)


    .. attribute:: BG_ERROR_CONTEXT_LOCAL_FILE(4)


    .. attribute:: BG_ERROR_CONTEXT_REMOTE_FILE(5)


    .. attribute:: BG_ERROR_CONTEXT_GENERAL_TRANSPORT(6)


    .. attribute:: BG_ERROR_CONTEXT_REMOTE_APPLICATION(7)

_BG_JOB_TYPE
''''''''''''
.. class:: BG_JOB_TYPE

    Alias for :class:`_BG_JOB_TYPE`


.. class:: _BG_JOB_TYPE


    .. attribute:: BG_JOB_TYPE_DOWNLOAD(0)


    .. attribute:: BG_JOB_TYPE_UPLOAD(1)


    .. attribute:: BG_JOB_TYPE_UPLOAD_REPLY(2)

_EVT_VARIANT_TYPE
'''''''''''''''''
.. class:: EVT_VARIANT_TYPE

    Alias for :class:`_EVT_VARIANT_TYPE`


.. class:: _EVT_VARIANT_TYPE


    .. attribute:: EvtVarTypeNull(0)


    .. attribute:: EvtVarTypeString(1)


    .. attribute:: EvtVarTypeAnsiString(2)


    .. attribute:: EvtVarTypeSByte(3)


    .. attribute:: EvtVarTypeByte(4)


    .. attribute:: EvtVarTypeInt16(5)


    .. attribute:: EvtVarTypeUInt16(6)


    .. attribute:: EvtVarTypeInt32(7)


    .. attribute:: EvtVarTypeUInt32(8)


    .. attribute:: EvtVarTypeInt64(9)


    .. attribute:: EvtVarTypeUInt64(10)


    .. attribute:: EvtVarTypeSingle(11)


    .. attribute:: EvtVarTypeDouble(12)


    .. attribute:: EvtVarTypeBoolean(13)


    .. attribute:: EvtVarTypeBinary(14)


    .. attribute:: EvtVarTypeGuid(15)


    .. attribute:: EvtVarTypeSizeT(16)


    .. attribute:: EvtVarTypeFileTime(17)


    .. attribute:: EvtVarTypeSysTime(18)


    .. attribute:: EvtVarTypeSid(19)


    .. attribute:: EvtVarTypeHexInt32(20)


    .. attribute:: EvtVarTypeHexInt64(21)


    .. attribute:: EvtVarTypeEvtHandle(32)


    .. attribute:: EvtVarTypeEvtXml(35)

_EVT_RENDER_CONTEXT_FLAGS
'''''''''''''''''''''''''
.. class:: EVT_RENDER_CONTEXT_FLAGS

    Alias for :class:`_EVT_RENDER_CONTEXT_FLAGS`


.. class:: _EVT_RENDER_CONTEXT_FLAGS


    .. attribute:: EvtRenderContextValues(0)


    .. attribute:: EvtRenderContextSystem(1)


    .. attribute:: EvtRenderContextUser(2)

_EVT_SYSTEM_PROPERTY_ID
'''''''''''''''''''''''
.. class:: EVT_SYSTEM_PROPERTY_ID

    Alias for :class:`_EVT_SYSTEM_PROPERTY_ID`


.. class:: _EVT_SYSTEM_PROPERTY_ID


    .. attribute:: EvtSystemProviderName(0)


    .. attribute:: EvtSystemProviderGuid(1)


    .. attribute:: EvtSystemEventID(2)


    .. attribute:: EvtSystemQualifiers(3)


    .. attribute:: EvtSystemLevel(4)


    .. attribute:: EvtSystemTask(5)


    .. attribute:: EvtSystemOpcode(6)


    .. attribute:: EvtSystemKeywords(7)


    .. attribute:: EvtSystemTimeCreated(8)


    .. attribute:: EvtSystemEventRecordId(9)


    .. attribute:: EvtSystemActivityID(10)


    .. attribute:: EvtSystemRelatedActivityID(11)


    .. attribute:: EvtSystemProcessID(12)


    .. attribute:: EvtSystemThreadID(13)


    .. attribute:: EvtSystemChannel(14)


    .. attribute:: EvtSystemComputer(15)


    .. attribute:: EvtSystemUserID(16)


    .. attribute:: EvtSystemVersion(17)


    .. attribute:: EvtSystemPropertyIdEND(18)

_EVT_RENDER_FLAGS
'''''''''''''''''
.. class:: EVT_RENDER_FLAGS

    Alias for :class:`_EVT_RENDER_FLAGS`


.. class:: _EVT_RENDER_FLAGS


    .. attribute:: EvtRenderEventValues(0)


    .. attribute:: EvtRenderEventXml(1)


    .. attribute:: EvtRenderBookmark(2)

_EVT_QUERY_FLAGS
''''''''''''''''
.. class:: EVT_QUERY_FLAGS

    Alias for :class:`_EVT_QUERY_FLAGS`


.. class:: _EVT_QUERY_FLAGS


    .. attribute:: EvtQueryChannelPath(1)


    .. attribute:: EvtQueryFilePath(2)


    .. attribute:: EvtQueryForwardDirection(256)


    .. attribute:: EvtQueryReverseDirection(512)


    .. attribute:: EvtQueryTolerateQueryErrors(4096)

_EVT_LOG_PROPERTY_ID
''''''''''''''''''''
.. class:: EVT_LOG_PROPERTY_ID

    Alias for :class:`_EVT_LOG_PROPERTY_ID`


.. class:: _EVT_LOG_PROPERTY_ID


    .. attribute:: EvtLogCreationTime(0)


    .. attribute:: EvtLogLastAccessTime(1)


    .. attribute:: EvtLogLastWriteTime(2)


    .. attribute:: EvtLogFileSize(3)


    .. attribute:: EvtLogAttributes(4)


    .. attribute:: EvtLogNumberOfLogRecords(5)


    .. attribute:: EvtLogOldestRecordNumber(6)


    .. attribute:: EvtLogFull(7)

_EVT_OPEN_LOG_FLAGS
'''''''''''''''''''
.. class:: EVT_OPEN_LOG_FLAGS

    Alias for :class:`_EVT_OPEN_LOG_FLAGS`


.. class:: _EVT_OPEN_LOG_FLAGS


    .. attribute:: EvtOpenChannelPath(1)


    .. attribute:: EvtOpenFilePath(2)

_EVT_CHANNEL_CONFIG_PROPERTY_ID
'''''''''''''''''''''''''''''''
.. class:: EVT_CHANNEL_CONFIG_PROPERTY_ID

    Alias for :class:`_EVT_CHANNEL_CONFIG_PROPERTY_ID`


.. class:: _EVT_CHANNEL_CONFIG_PROPERTY_ID


    .. attribute:: EvtChannelConfigEnabled(0)


    .. attribute:: EvtChannelConfigIsolation(1)


    .. attribute:: EvtChannelConfigType(2)


    .. attribute:: EvtChannelConfigOwningPublisher(3)


    .. attribute:: EvtChannelConfigClassicEventlog(4)


    .. attribute:: EvtChannelConfigAccess(5)


    .. attribute:: EvtChannelLoggingConfigRetention(6)


    .. attribute:: EvtChannelLoggingConfigAutoBackup(7)


    .. attribute:: EvtChannelLoggingConfigMaxSize(8)


    .. attribute:: EvtChannelLoggingConfigLogFilePath(9)


    .. attribute:: EvtChannelPublishingConfigLevel(10)


    .. attribute:: EvtChannelPublishingConfigKeywords(11)


    .. attribute:: EvtChannelPublishingConfigControlGuid(12)


    .. attribute:: EvtChannelPublishingConfigBufferSize(13)


    .. attribute:: EvtChannelPublishingConfigMinBuffers(14)


    .. attribute:: EvtChannelPublishingConfigMaxBuffers(15)


    .. attribute:: EvtChannelPublishingConfigLatency(16)


    .. attribute:: EvtChannelPublishingConfigClockType(17)


    .. attribute:: EvtChannelPublishingConfigSidType(18)


    .. attribute:: EvtChannelPublisherList(19)


    .. attribute:: EvtChannelPublishingConfigFileMax(20)


    .. attribute:: EvtChannelConfigPropertyIdEND(21)

_EVT_CHANNEL_TYPE
'''''''''''''''''
.. class:: EVT_CHANNEL_TYPE

    Alias for :class:`_EVT_CHANNEL_TYPE`


.. class:: _EVT_CHANNEL_TYPE


    .. attribute:: EvtChannelTypeAdmin(0)


    .. attribute:: EvtChannelTypeOperational(1)


    .. attribute:: EvtChannelTypeAnalytic(2)


    .. attribute:: EvtChannelTypeDebug(3)

_EVT_CHANNEL_ISOLATION_TYPE
'''''''''''''''''''''''''''
.. class:: EVT_CHANNEL_ISOLATION_TYPE

    Alias for :class:`_EVT_CHANNEL_ISOLATION_TYPE`


.. class:: _EVT_CHANNEL_ISOLATION_TYPE


    .. attribute:: EvtChannelIsolationTypeApplication(0)


    .. attribute:: EvtChannelIsolationTypeSystem(1)


    .. attribute:: EvtChannelIsolationTypeCustom(2)

_EVT_EVENT_METADATA_PROPERTY_ID
'''''''''''''''''''''''''''''''
.. class:: EVT_EVENT_METADATA_PROPERTY_ID

    Alias for :class:`_EVT_EVENT_METADATA_PROPERTY_ID`


.. class:: _EVT_EVENT_METADATA_PROPERTY_ID


    .. attribute:: EventMetadataEventID(0)


    .. attribute:: EventMetadataEventVersion(1)


    .. attribute:: EventMetadataEventChannel(2)


    .. attribute:: EventMetadataEventLevel(3)


    .. attribute:: EventMetadataEventOpcode(4)


    .. attribute:: EventMetadataEventTask(5)


    .. attribute:: EventMetadataEventKeyword(6)


    .. attribute:: EventMetadataEventMessageID(7)


    .. attribute:: EventMetadataEventTemplate(8)


    .. attribute:: EvtEventMetadataPropertyIdEND(9)

_EVT_PUBLISHER_METADATA_PROPERTY_ID
'''''''''''''''''''''''''''''''''''
.. class:: EVT_PUBLISHER_METADATA_PROPERTY_ID

    Alias for :class:`_EVT_PUBLISHER_METADATA_PROPERTY_ID`


.. class:: _EVT_PUBLISHER_METADATA_PROPERTY_ID


    .. attribute:: EvtPublisherMetadataPublisherGuid(0)


    .. attribute:: EvtPublisherMetadataResourceFilePath(1)


    .. attribute:: EvtPublisherMetadataParameterFilePath(2)


    .. attribute:: EvtPublisherMetadataMessageFilePath(3)


    .. attribute:: EvtPublisherMetadataHelpLink(4)


    .. attribute:: EvtPublisherMetadataPublisherMessageID(5)


    .. attribute:: EvtPublisherMetadataChannelReferences(6)


    .. attribute:: EvtPublisherMetadataChannelReferencePath(7)


    .. attribute:: EvtPublisherMetadataChannelReferenceIndex(8)


    .. attribute:: EvtPublisherMetadataChannelReferenceID(9)


    .. attribute:: EvtPublisherMetadataChannelReferenceFlags(10)


    .. attribute:: EvtPublisherMetadataChannelReferenceMessageID(11)


    .. attribute:: EvtPublisherMetadataLevels(12)


    .. attribute:: EvtPublisherMetadataLevelName(13)


    .. attribute:: EvtPublisherMetadataLevelValue(14)


    .. attribute:: EvtPublisherMetadataLevelMessageID(15)


    .. attribute:: EvtPublisherMetadataTasks(16)


    .. attribute:: EvtPublisherMetadataTaskName(17)


    .. attribute:: EvtPublisherMetadataTaskEventGuid(18)


    .. attribute:: EvtPublisherMetadataTaskValue(19)


    .. attribute:: EvtPublisherMetadataTaskMessageID(20)


    .. attribute:: EvtPublisherMetadataOpcodes(21)


    .. attribute:: EvtPublisherMetadataOpcodeName(22)


    .. attribute:: EvtPublisherMetadataOpcodeValue(23)


    .. attribute:: EvtPublisherMetadataOpcodeMessageID(24)


    .. attribute:: EvtPublisherMetadataKeywords(25)


    .. attribute:: EvtPublisherMetadataKeywordName(26)


    .. attribute:: EvtPublisherMetadataKeywordValue(27)


    .. attribute:: EvtPublisherMetadataKeywordMessageID(28)


    .. attribute:: EvtPublisherMetadataPropertyIdEND(29)

_EVT_FORMAT_MESSAGE_FLAGS
'''''''''''''''''''''''''
.. class:: EVT_FORMAT_MESSAGE_FLAGS

    Alias for :class:`_EVT_FORMAT_MESSAGE_FLAGS`


.. class:: _EVT_FORMAT_MESSAGE_FLAGS


    .. attribute:: EvtFormatMessageEvent(1)


    .. attribute:: EvtFormatMessageLevel(2)


    .. attribute:: EvtFormatMessageTask(3)


    .. attribute:: EvtFormatMessageOpcode(4)


    .. attribute:: EvtFormatMessageKeyword(5)


    .. attribute:: EvtFormatMessageChannel(6)


    .. attribute:: EvtFormatMessageProvider(7)


    .. attribute:: EvtFormatMessageId(8)


    .. attribute:: EvtFormatMessageXml(9)

_FILE_INFORMATION_CLASS
'''''''''''''''''''''''
.. class:: FILE_INFORMATION_CLASS

    Alias for :class:`_FILE_INFORMATION_CLASS`


.. class:: PFILE_INFORMATION_CLASS

    Pointer to :class:`_FILE_INFORMATION_CLASS`


.. class:: _FILE_INFORMATION_CLASS


    .. attribute:: FakeFileInformationZero(0)


    .. attribute:: FileDirectoryInformation(1)


    .. attribute:: FileFullDirectoryInformation(2)


    .. attribute:: FileBothDirectoryInformation(3)


    .. attribute:: FileBasicInformation(4)


    .. attribute:: FileStandardInformation(5)


    .. attribute:: FileInternalInformation(6)


    .. attribute:: FileEaInformation(7)


    .. attribute:: FileAccessInformation(8)


    .. attribute:: FileNameInformation(9)


    .. attribute:: FileRenameInformation(10)


    .. attribute:: FileLinkInformation(11)


    .. attribute:: FileNamesInformation(12)


    .. attribute:: FileDispositionInformation(13)


    .. attribute:: FilePositionInformation(14)


    .. attribute:: FileFullEaInformation(15)


    .. attribute:: FileModeInformation(16)


    .. attribute:: FileAlignmentInformation(17)


    .. attribute:: FileAllInformation(18)


    .. attribute:: FileAllocationInformation(19)


    .. attribute:: FileEndOfFileInformation(20)


    .. attribute:: FileAlternateNameInformation(21)


    .. attribute:: FileStreamInformation(22)


    .. attribute:: FilePipeInformation(23)


    .. attribute:: FilePipeLocalInformation(24)


    .. attribute:: FilePipeRemoteInformation(25)


    .. attribute:: FileMailslotQueryInformation(26)


    .. attribute:: FileMailslotSetInformation(27)


    .. attribute:: FileCompressionInformation(28)


    .. attribute:: FileObjectIdInformation(29)


    .. attribute:: FileCompletionInformation(30)


    .. attribute:: FileMoveClusterInformation(31)


    .. attribute:: FileQuotaInformation(32)


    .. attribute:: FileReparsePointInformation(33)


    .. attribute:: FileNetworkOpenInformation(34)


    .. attribute:: FileAttributeTagInformation(35)


    .. attribute:: FileTrackingInformation(36)


    .. attribute:: FileIdBothDirectoryInformation(37)


    .. attribute:: FileIdFullDirectoryInformation(38)


    .. attribute:: FileValidDataLengthInformation(39)


    .. attribute:: FileShortNameInformation(40)


    .. attribute:: FileIoCompletionNotificationInformation(41)


    .. attribute:: FileIoStatusBlockRangeInformation(42)


    .. attribute:: FileIoPriorityHintInformation(43)


    .. attribute:: FileSfioReserveInformation(44)


    .. attribute:: FileSfioVolumeInformation(45)


    .. attribute:: FileHardLinkInformation(46)


    .. attribute:: FileProcessIdsUsingFileInformation(47)


    .. attribute:: FileNormalizedNameInformation(48)


    .. attribute:: FileNetworkPhysicalNameInformation(49)


    .. attribute:: FileIdGlobalTxDirectoryInformation(50)


    .. attribute:: FileIsRemoteDeviceInformation(51)


    .. attribute:: FileUnusedInformation(52)


    .. attribute:: FileNumaNodeInformation(53)


    .. attribute:: FileStandardLinkInformation(54)


    .. attribute:: FileRemoteProtocolInformation(55)


    .. attribute:: FileRenameInformationBypassAccessCheck(56)


    .. attribute:: FileLinkInformationBypassAccessCheck(57)


    .. attribute:: FileVolumeNameInformation(58)


    .. attribute:: FileIdInformation(59)


    .. attribute:: FileIdExtdDirectoryInformation(60)


    .. attribute:: FileReplaceCompletionInformation(61)


    .. attribute:: FileHardLinkFullIdInformation(62)


    .. attribute:: FileIdExtdBothDirectoryInformation(63)


    .. attribute:: FileDispositionInformationEx(64)


    .. attribute:: FileRenameInformationEx(65)


    .. attribute:: FileRenameInformationExBypassAccessCheck(66)


    .. attribute:: FileMaximumInformation(67)

_IO_PRIORITY_HINT
'''''''''''''''''
.. class:: IO_PRIORITY_HINT

    Alias for :class:`_IO_PRIORITY_HINT`


.. class:: _IO_PRIORITY_HINT


    .. attribute:: IoPriorityVeryLow(0)


    .. attribute:: IoPriorityLow(1)


    .. attribute:: IoPriorityNormal(2)


    .. attribute:: IoPriorityHigh(3)


    .. attribute:: IoPriorityCritical(4)


    .. attribute:: MaxIoPriorityTypes(5)

