import StringIO
from collections import namedtuple

import dummy_wintypes
import struct_parser
from winstruct import WinStruct, WinUnion, WinStructType, Ptr, WinEnum
from simpleparser import *


def initial_processing( data):
    #  https://gcc.gnu.org/onlinedocs/cpp/Initial-processing.html#Initial-processing
    # Step 1 -> use correct end of line + add last \n if not existing
    data = data.replace("\r\n", "\n")
    if not data.endswith("\n"):
        data = data + "\n"
    # Step 2: Trigraph : fuck it
    pass
    # Step 3: Line merge !
    data = data.replace("\\\n", "")
    # Step 4 Remove comments:

    ins = StringIO.StringIO(data)
    outs = StringIO.StringIO()

    in_str = False
    res = []
    while ins.tell() != len(data):
        c = ins.read(1)
        if ins.tell() == len(data):
            outs.write(c)
            break
        if not in_str and c == "/":
            nc = ins.read(1)
            if nc  == "/":
                while c != "\n":
                    c = ins.read(1)
                outs.write(c)
                continue
            elif nc == "*":
                while c != "*" or nc != "/":
                    c = nc
                    nc = ins.read(1)
                    if not nc:
                        raise ValueError("Unmatched */")
                outs.write(" ")
                continue
            else:
                outs.write(c)
                ins.seek(ins.tell() - 1)
                continue
        # TODO: escape in str
        elif c == '"':
            in_str = not in_str
        outs.write(c)
    outs.seek(0)
    return outs.read()

class WinComParser(Parser):
    PARAM_INFO =  ["__RPC__deref_out", "__RPC__in", "__RPC__deref_out_opt", "__RPC__out", "__RPC__in_opt",
        "__RPC__deref_opt_inout_opt", "__in", "__out", "__out_opt", "__in_opt", "__inout",
        "__reserved"]
    PARAM_INFO_WITH_VALUE = ["__RPC__in_ecount", "__RPC__out_ecount_part", "__RPC__in_ecount_full",
            "__RPC__in_range", "__RPC__out_ecount_full", "__out_ecount_opt", "__out_ecount", "__in_ecount_opt",
            "__in_ecount", "__out_bcount_opt", "__out_bcount", "__in_bcount", "__in_bcount_opt"]

    def __init__(self, data):
        data = initial_processing(data)
        #print(data)
        super(WinComParser, self).__init__(data)

    def assert_name(self, expected_name, n=None):
        if n is None:
            n = self.assert_token_type(NameToken)
        if n.value != expected_name:
            raise ParsingError("Expected name {0} got {1} instead".format(expected_name, n.value))
        return n

    def parse_argument(self):
        byreflevel = 0
        # Pass __RPC__deref_out
        while self.peek() in [NameToken(x) for x in self.PARAM_INFO + self.PARAM_INFO_WITH_VALUE]:
            ign = self.assert_token_type(NameToken)
            if ign.value in self.PARAM_INFO_WITH_VALUE:
                # pass __RPC__in_ecount(cNames)
                self.assert_token_type(OpenParenthesisToken)
                while type(self.peek()) != CloseParenthesisToken:
                    self.next_token()
                self.next_token()
        if self.peek() == KeywordToken("const"):
            self.next_token()
        type_name = self.assert_token_type(NameToken)
        if type_name.value.startswith("_"):
            print("type_name = <{0}> might be a PARAM_INFO".format(type_name.value))

        while type(self.peek()) == StarToken:
            byreflevel += 1
            discard_star = self.next_token()
        arg_name = self.assert_token_type(NameToken)
        if type(self.peek()) not in [CommaToken, CloseParenthesisToken]:
            raise ParsingError("COM PARSING: argument decl should finish by <,> or <)> (arg {0})".format(type_name.value))
        if type(self.peek()) == CommaToken:
            self.assert_token_type(CommaToken)
        return type_name.value, byreflevel, arg_name.value

    def parse_method(self):
        ret_type = self.assert_token_type(NameToken)
        #print(ret_type)
        self.assert_token_type(OpenParenthesisToken)
        self.assert_name("STDMETHODCALLTYPE")
        #if type(self.peek()) == StarToken:
        self.assert_token_type(StarToken)
        method_name = self.assert_token_type(NameToken)
        #print("Parsing method <{0}>".format(method_name))
        self.assert_token_type(CloseParenthesisToken)


        args = []
        self.assert_token_type(OpenParenthesisToken)
        while type(self.peek()) != CloseParenthesisToken:
            # TODO: handle call with VARGS ?
            if self.peek().value == "...":
                self.next_token()
                continue
            args.append(self.parse_argument())
            #print("Pass <{0}>".format(p))
        self.next_token()
        self.assert_token_type(ColonToken)
        return ret_type.value, method_name.value, args

    def parse(self):
        tok = self.peek()
        if type(tok) == NameToken and tok.value == "@IID:":
            self.next_token()
            iid = self.assert_token_type(NameToken).value
        else:
            iid = None
        self.assert_keyword("typedef")
        self.assert_keyword("struct")

        vtable_name = self.assert_token_type(NameToken).value
        self.assert_token_type(OpenBracketToken)
        self.assert_name("BEGIN_INTERFACE")

        res = WinCOMVTABLE(vtable_name)
        res.iid = iid

        while self.peek() != NameToken("END_INTERFACE"):
            ret_type, method_name, args = self.parse_method()
            #print("Method name is {0}".format(method_name))
            for arg in args:
                pass
                #print("    Param is {0}".format(arg))
            res.add_method(ret_type, method_name, args)
        end_interface = self.assert_name("END_INTERFACE")
        self.assert_token_type(CloseBracketToken)
        typdef = self.assert_token_type(NameToken)
        # Do a real thing able to see multiple typedef..
        typedefptr = None
        if type(self.peek()) == CommaToken:
            self.next_token()
            self.assert_token_type(StarToken)
            typedefptr = self.assert_token_type(NameToken).value
        self.assert_token_type(ColonToken)
        res.typedefptr = typedefptr
        return res

        #print(self.data)

Method = namedtuple("Method", ["ret_type", "name", "args"])
MethodArg = namedtuple("MethodArg", ["type", "byreflevel", "name"])
class WinCOMVTABLE(object):
    def __init__(self, vtbl_name):
        self.vtbl_name = vtbl_name
        if not vtbl_name.endswith("Vtbl"):
            raise ValueError("Com interface are expected to finish by <Vtbl> got <{0}".format(vtbl.name))
        self.name = vtbl_name[:-len("Vtbl")]
        self.methods = []

    def add_method(self, ret_type, method_name, args):
        new_args = []
        for type, byreflevel, name in args:
            if type in ["long", "int"]:
                type = type.upper()
            new_args.append(MethodArg(type, byreflevel, name))

        if ret_type in ["long", "int"]:
            ret_type = ret_type.upper()
        self.methods.append(Method(ret_type, method_name, new_args))


if __name__ == "__main__":
    import sys
    x = WinComParser(open(sys.argv[1]).read()).parse()
    print(x)