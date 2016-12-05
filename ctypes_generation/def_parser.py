from winstruct import WinStruct, WinStructType, Ptr
import dummy_wintypes
from simpleparser import *
import re

class WinDef(object):
    def __init__(self, name, code):
        self.name = name
        self.code = code
        
    def generate_ctypes(self):
        return """{0} = make_flag("{0}", {1})""".format(self.name, self.code)

class WinDefParser(Parser):

    def parse_define(self):
        self.assert_token_type(SharpToken)
        define = self.assert_token_type(NameToken)
        if define.value.lower() != "define":
            raise ValueError("Expection #define got #{0} instead".format(define.value))
        define_name = self.assert_token_type(NameToken)
        define_value = []
        while self.peek() is not None and type(self.peek()) is not SharpToken:
            v = self.next_token().value
            if v.lower().startswith("0x") and v[-1] == "L":
                v = v[:-1]
            define_value.append(v)
        return WinDef(define_name.value, " ".join(define_value))
        
    def parse(self):
        res = []
        while self.peek() is not None:
            res.append(self.parse_define())
        return res 