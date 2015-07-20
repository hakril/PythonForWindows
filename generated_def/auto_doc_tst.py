def pretty_print_ctypes_type(t):
    format = "{0}"
    if issubclass(t, ctypes.Array):
        format = "[{0}" + "* {0}]".format(t._length_)
        t = t._type_
      
    if issubclass(t, ctypes._Pointer):
        format = format.format("Pointer({0})")
        t = t._type_

    if issubclass(t, ctypes.Structure):
        return format.format(":class:`{0}`".format(t.__name__))
    return t
    

def autodoc_ctypes_struct(struct):
    doc = ["fields:"]
    for name, type in struct._fields_:
        doc.append("     {0} -> {1}".format(name, pretty_print_ctypes_type(type)))
        
    struct.__doc__ = "\n\n".join(doc)
    return struct