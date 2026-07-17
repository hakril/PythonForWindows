
_original__tagVARIANT = __tagVARIANT
class __tagVARIANT(__tagVARIANT):
    VT_TYPE_TO_FIELD = {
        # Fundamental Types
        VT_EMPTY: None,
        VT_NULL: None,
        VT_I2: "iVal",
        VT_I4: "lVal",
        VT_R4: "fltVal",
        VT_R8: "dblVal",
        VT_CY: "cyVal",
        VT_DATE: "date",
        VT_BSTR: "bstrVal",
        VT_DISPATCH: "pdispVal",
        VT_ERROR: "scode",
        VT_BOOL: "boolVal",
        VT_VARIANT: "pvarVal",  # Only used with VT_BYREF
        VT_UNKNOWN: "punkVal",
        VT_DECIMAL: "decVal",   # Note: decVal sits parallel to the inner struct layout, handled via union
        VT_I1: "cVal",
        VT_UI1: "bVal",
        VT_UI2: "uiVal",
        VT_UI4: "ulVal",
        VT_I8: "llVal",
        VT_UI8: "ullVal",
        VT_INT: "intVal",
        VT_UINT: "uintVal",
        VT_VOID: "byref",       # Generic raw pointer
        VT_HRESULT: "scode",
        VT_PTR: "byref",
        VT_SAFEARRAY: "parray",
        VT_CARRAY: "byref",
        VT_USERDEFINED: "byref",
        VT_RECORD: "pvRecord",  # Access via __VARIANT_NAME_4 struct inside the union

        # Pointer variants (VT_BYREF combinations)
        VT_I2 | VT_BYREF: "piVal",
        VT_I4 | VT_BYREF: "plVal",
        VT_R4 | VT_BYREF: "pfltVal",
        VT_R8 | VT_BYREF: "pdblVal",
        VT_CY | VT_BYREF: "pcyVal",
        VT_DATE | VT_BYREF: "pdate",
        VT_BSTR | VT_BYREF: "pbstrVal",
        VT_DISPATCH | VT_BYREF: "ppdispVal",
        VT_ERROR | VT_BYREF: "pscode",
        VT_BOOL | VT_BYREF: "pboolVal",
        VT_VARIANT | VT_BYREF: "pvarVal",
        VT_UNKNOWN | VT_BYREF: "ppunkVal",
        VT_SAFEARRAY | VT_BYREF: "pparray",
        VT_DECIMAL | VT_BYREF: "pdecVal",
        VT_I1 | VT_BYREF: "pcVal",
        VT_UI1 | VT_BYREF: "pbVal",
        VT_UI2 | VT_BYREF: "puiVal",
        VT_UI4 | VT_BYREF: "pulVal",
        VT_I8 | VT_BYREF: "pllVal",
        VT_UI8 | VT_BYREF: "pullVal",
        VT_INT | VT_BYREF: "pintVal",
        VT_UINT | VT_BYREF: "puintVal",
    }

    # # Copy raw-ctypes fields which is a descriptor :)
    # Allow to redefine the vt with type and allow access to the undervalue here
    rawvt = _original__tagVARIANT.vt

    def get_vt(self):
        # Depending on a typedef is not perfect, but name with __ at start break python
        # NameError: name '_tagVARIANT__tagVARIANT' is not defined
        rawvt = super(VARIANT, self).vt
        return VARENUM.mapper[self.rawvt]

    def set_vt(self, value):
        self.rawvt = value

    vt = property(get_vt, set_vt)

    @property
    def value(self):
        fieldname = self.VT_TYPE_TO_FIELD[self.rawvt]
        value = getattr(self, fieldname)
        if self.rawvt == VT_UNKNOWN:
            value = windows.generated_def.IUnknown(value)
        return value

    @classmethod
    def create(cls, value, type=None):
        if type is None:
            return cls._create_with_guessed_type(value)
        return cls._create_with_fixed_type(value, type)

    @classmethod
    def _create_with_guessed_type(cls, value):
        # TODO : better
        if value is None:
            return cls(VT_NULL)
        if isinstance(value, bool):
            return cls(VT_BOOL, boolVal=value)
        if isinstance(value, int):
            return cls(VT_INT, intVal=value) # Default on llval ? int-val ?
        if isinstance(value, str): # TODO: py2/py3
            return cls(VT_BSTR, bstrVal=value)
        raise ValueError("Could not guess VARIANT type for value {}".format(value))

    @classmethod
    def _create_with_fixed_type(cls, value, type):
        if type in (VT_EMPTY, VT_NULL):
            return cls(vt=type)
        targetfield = cls.VT_TYPE_TO_FIELD[type]
        return cls(vt=type, **{targetfield: value})

    def __repr__(self):
        return "<{0} type={1}>".format(type(self).__name__, VARENUM.mapper[self.vt])