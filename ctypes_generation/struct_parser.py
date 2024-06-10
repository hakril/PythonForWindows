import dummy_wintypes
import itertools
from winstruct import WinStruct, WinUnion, WinStructType, Ptr, WinEnum, BitFieldValue, ComplexArrayExpression
from simpleparser import *



class WinStructParser(Parser):
    def __init__(self, *args, **kwargs):
        super(WinStructParser, self).__init__(*args, **kwargs)
        self.pack = None

    def parse_array_or_bitfield(self):
        if type(self.peek()) == OpenSquareBracketToken:
            # Array
            self.assert_token_type(OpenSquareBracketToken)
            nb_rep = ComplexArrayExpression()
            while type(self.peek()) != CloseSquareBracketToken:
                tok = self.next_token()
                if type(tok) not in (NameToken, PlusToken, StarToken):
                    raise ValueError("Array expression only accept names/+/*")
                is_name = (type(tok) == NameToken)
                nb_rep.add_token_to_expression(tok.value, is_name)
            self.assert_token_type(CloseSquareBracketToken)
            return nb_rep # YOLO, import
        # Bitfield
        self.assert_token_type(ColonToken)
        nb_bits = self.promote_to_int(self.next_token())
        return BitFieldValue(nb_bits)


    def parse_def(self):
        if type(self.peek()) != NameToken and self.peek() in (KeywordToken("union"), KeywordToken("struct")):
            # Anonymous union-structure :)
            # kword = self.assert_token_type(KeywordToken)
            # Not a name. Anon union/struct ?
            subdef_type = self.next_token() # union / struct
            if type(self.peek()) == OpenBracketToken:
                sub = self.parse_winstruct(anonymous=True, anon_type=subdef_type)
                return (sub, NameToken(None), 1)
            else:
                # struct _MYNAME_ -> no anon juste the name of the struct.
                # Nothing special: juste drop the struct
                assert subdef_type.value == "struct"
                # Name will be enforced by nest line.

        def_type_tok  = self.assert_token_type(NameToken)
        def_type = WinStructType(def_type_tok.value)
        if type(self.peek()) == StarToken:
            def_type = Ptr(def_type)
            discard_star = self.next_token()

        def_name = self.assert_token_type(NameToken)

        if type(self.peek()) == SemiColonToken:
            self.next_token()
            return (def_type, def_name, 1)

        number_rep = self.parse_array_or_bitfield()
        self.assert_token_type(SemiColonToken)
        return (def_type, def_name, number_rep)

    def parse_typedef(self, struct):
        if type(self.peek()) == SemiColonToken: # Just a ; no typedef
            self.next_token()
            return
        sep = CommaToken()
        while type(sep) == CommaToken:
            add_to_typedef = struct.add_typedef
            if type(self.peek()) == StarToken:
                self.next_token()
                add_to_typedef = struct.add_ptr_typedef
            name = self.assert_token_type(NameToken)
            # UGLY HACK for LDR definition
            if name.value == "RESTRICTED_POINTER":
                name = self.assert_token_type(NameToken)
            add_to_typedef(name.value)
            sep = self.next_token()
        self.assert_token_type(SemiColonToken, sep)

    def parse_enum(self, is_typedef):
        """Handle enum typedef with no value assignement and 1 typedef after"""
        if not type(self.peek()) == OpenBracketToken:
            # Not an ANON enum
            enum_name = self.assert_token_type(NameToken).value
            res_enum = WinEnum(enum_name)
        else:
            if not is_typedef:
                raise ValueError("Anonymous union not in a typedef")
            enum_name = "<anonymous>"
            res_enum = WinEnum(None)

        self.assert_token_type(OpenBracketToken)
        count = itertools.count()
        while type(self.peek()) != CloseBracketToken:
            i = next(count)
            name = self.assert_token_type(NameToken)
            if type(self.peek()) == EqualToken:
                # Equal sign (hard define of enum value)
                self.assert_token_type(EqualToken)
                i = self.promote_to_int(self.next_token())
                # print(i, new_i)
                # assert new_i >= i, "Cannot define eum value with inferior current value ({0})".format(enum_name)
                # Setup new counter from here
                count = itertools.count(i + 1)
            res_enum.add_enum_entry(i, name.value)
            if not type(self.peek()) == CloseBracketToken:
                self.assert_token_type(CommaToken)

        self.assert_token_type(CloseBracketToken)
        self.parse_typedef(res_enum)
        #other_name = self.assert_token_type(NameToken).value
        #res_enum.add_typedef(other_name)
        #self.assert_token_type(SemiColonToken)
        return res_enum


    def parse_winstruct(self, anonymous=False, anon_type=None):
        is_typedef = False
        peeked = self.peek()
        if peeked == KeywordToken("typedef"):
            self.assert_keyword("typedef")
            is_typedef = True

        if not anonymous:
            def_type = self.assert_token_type(KeywordToken)
        else:
            def_type = anon_type # Hack car le lexeing a ete fait avant, l'info est donc passee en param.
        if def_type.value == "enum":
            return self.parse_enum(is_typedef)
        if def_type.value == "struct":
            WinDefType = WinStruct
        elif def_type.value == "union":
            WinDefType = WinUnion
        else:
            raise ParsingError("Expecting union or struct got <{0}> instead".format(def_type.value))
        if not type(self.peek()) == OpenBracketToken:
            # Not an anonymous structure def
            struct_name = self.assert_token_type(NameToken).value
        else:
            # Anonymous structure def: check if we are ina typedef
            if not is_typedef and not anonymous:
                raise ValueError("Anonymous structure/union not in a typedef")
            struct_name = None
        self.assert_token_type(OpenBracketToken)

        result = WinDefType(struct_name, self.pack)
        while type(self.peek()) != CloseBracketToken:
            tok_type, tok_name, nb_rep = self.parse_def()
            result.add_field((tok_type, tok_name.value, nb_rep))
        self.assert_token_type(CloseBracketToken)
        if is_typedef:
            self.parse_typedef(result)
        elif anonymous:
            if type(self.peek()) == NameToken:
                result.add_typedef(self.assert_token_type(NameToken).value)
            self.assert_token_type(SemiColonToken)
        else:
            self.assert_token_type(SemiColonToken)
        return result

    def parse(self):
        strucs = []
        enums = []
        while self.peek() is not None:
            # HANDLE PRAGMA_PACK / PRAGMA_NOPACK
            if type(self.peek()) == NameToken:
                pragma = self.next_token().value
                if pragma == "PRAGMA_NOPACK":
                    self.pack = None
                    continue
                if pragma != "PRAGMA_PACK":
                    raise ValueError("Expected struct/union def or PRAGMA_[NO]PACK")
                pack_value = self.promote_to_int(self.next_token())
                self.pack = pack_value

            x = self.parse_winstruct()
            #x.packing = self.pack
            #if x.packing != None:
            #    print("{0} pack = {1}".format(x.name, x.packing))
            if type(x) == WinStruct or type(x) == WinUnion:
                strucs.append(x)
            elif type(x) == WinEnum:
                enums.append(x)
            else:
                raise ValueError("Unknow returned type {0}".format(x))
        return strucs, enums

class SimpleTypeDefine(object):
    def __init__(self, lvalue,  rvalue):
        self.lvalue = lvalue
        self.rvalue = rvalue

    def generate_ctypes(self):
        return "{self.lvalue} = {self.rvalue}".format(self=self)

class SimpleTypesParser(Parser):
    def __init__(self, data):
        self.lexer = iter(Lexer(self.initial_processing(data), newlinetoken=True))
        self.peek_token = None

    def parse(self):
        results = []
        while self.peek() is not None:
            lvalue = self.assert_token_type(NameToken).value
            self.assert_token_type(EqualToken)
            rvalue = ""
            while type(self.peek()) is not NewLineToken:
                rvalue += self.next_token().value
            results.append(SimpleTypeDefine(lvalue, rvalue))
            while type(self.peek()) is NewLineToken: # discard the NewLineToken(s)
                self.next_token()
        return results


if __name__ == "__main__":
    import sys
    #data = open(sys.argv[1], 'r').read()
    #ctypes_code = generate_ctypes(data)
