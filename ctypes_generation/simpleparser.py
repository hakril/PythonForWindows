import collections
import StringIO

TupleToken = collections.namedtuple('Token', ['value'])

class Token(TupleToken):
    def __repr__(self):
        return "{0}(value={1})".format(type(self).__name__, self.value)

TupleNoValueToken = collections.namedtuple('Token', [])

class NoValueToken(TupleNoValueToken):
    value = None
    def __repr__(self):
        return "{0}()".format(type(self).__name__)

class KeywordToken(Token):
    pass

class TypeToken(Token):
    pass

class NameToken(Token):
    pass

class ColonToken(NoValueToken):
    value = ";"
    pass

class CommaToken(NoValueToken):
    value = ","
    pass

class StarToken(NoValueToken):
    value = "*"
    pass

class OpenBracketToken(NoValueToken):
    value = "{"
    pass

class CloseBracketToken(NoValueToken):
    value = "}"
    pass

class OpenSquareBracketToken(NoValueToken):
    value = "["
    pass

class CloseSquareBracketToken(NoValueToken):
    value = "]"
    pass

class OpenParenthesisToken(NoValueToken):
    value = "("
    pass

class CloseParenthesisToken(NoValueToken):
    value = ")"
    pass

class SharpToken(NoValueToken):
    value = "#"
    pass

class EqualToken(NoValueToken):
    value = "="

class NewLineToken(NoValueToken):
    value = "\n"

class Lexer(object):
    keywords = ["typedef", "struct", "enum", "union", "const"]

    token_chr = {"*" : StarToken, "[" : OpenSquareBracketToken, "]" : CloseSquareBracketToken,
                    "{" : OpenBracketToken, "}" : CloseBracketToken, ";" : ColonToken,
                    "," : CommaToken, "(" : OpenParenthesisToken, ")" :  CloseParenthesisToken, "#" : SharpToken, "=" : EqualToken}

    def __init__(self, code, newlinetoken=False):
        self.code = code
        self.newlinetoken = newlinetoken

    def split_line(self, line):
        return line.strip().split()

    def is_keyword(self, word):
        return word in self.keywords

    def split_word(self, word):
        """Slit a dummy name with all token_chr"""
        queue = [None, word]
        for name in iter(queue.pop, None):
            if name in self.token_chr:
                yield self.token_chr[name]()
                continue
            if not any(spec_chr in name for spec_chr in self.token_chr):
                yield NameToken(name)
                continue
            new_tokens = [name]
            for spec_chr in self.token_chr:
                new_tokens = list(new_tokens[0].partition(spec_chr)) + new_tokens[1:]
            queue.extend(reversed([x for x in new_tokens if x]))

    def __iter__(self):
        for line in self.code.split("\n"):
            for word in self.split_line(line):
                if self.is_keyword(word):
                    yield KeywordToken(word)
                    continue
                for tok in self.split_word(word):
                    yield tok
            if self.newlinetoken:
                yield NewLineToken()



class ParsingError(Exception):
    pass

class Parser(object):
    def __init__(self, data):
        self.lexer = iter(Lexer(self.initial_processing(data)))
        self.peek_token = None

    def assert_keyword(self, expected_keyword, n=None):
        if n is None:
            n = self.assert_token_type(KeywordToken)
        if n.value != expected_keyword:
            raise ParsingError("Expected Keyword {0} got {1} instead".format(expected_keyword, n.value))
        return n

    def assert_token_type(self, expected_type, n=None):
        if n is None:
            n = self.next_token()
        if type(n) != expected_type:
            raise ParsingError("Expected type {0} and got {1} instead".format(expected_type.__name__, n))
        return n

    def assert_argument_io_info(self):
        io_info = self.assert_token_type(NameToken)
        if io_info.value not in self.known_io_info_type:
            raise ParsingError("Was expection IO_INFO got {0} instead".format(winapi))
        return io_info

    def promote_to_type(self, token):
        self.assert_token_type(NameToken, token)
        return TypeToken(token.value)

    def promote_to_int(self, token):
        self.assert_token_type(NameToken, token)
        try:
            return int(token.value)
        except ValueError:
            return int(token.value, 0)

    def next_token(self):
        if self.peek_token is not None:
            res = self.peek_token
            self.peek_token = None
            return res
        return next(self.lexer, None)

    def peek(self):
        if self.peek_token is None:
            self.peek_token = self.next_token()
        return self.peek_token

    def parse(self):
        raise NotImplementedError("Parser.parse()")

    def initial_processing(self, data):
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


#KNOWN_TYPE = ["BYTE", "USHORT", "DWORD", "PVOID", "ULONG", "HANDLE", "PWSTR"]
#
#def validate_structs(structs):
#    by_name = dict([(struct.name, struct) for struct in structs])
#    if len(by_name) != len(structs):
#        raise ValueError('2 structs with the same name')
#
#    for struct in structs:
#        for name, value in struct.typedef.items():
#            by_name[name] = value
#
#    for struct in structs:
#        for field_type, field_name, nb_rep in struct.fields:
#            if field_type.name not in KNOWN_TYPE:
#                print("non standard type : {0}".format(field_type))
#                if field_type.name not in by_name:
#                    print("UNKNOW TYPE {0}".format(field_type))
#
#    return structs
#
#
#
#data = open("winfunc.txt", "r").read()
#
#
#def dbg_lexer(data):
#    for i in Lexer(data).token_generation():
#        print i
#
#def dbg_parser(data):
#    return Parser(data).parse()
#
#def dbg_validate(data):
#    return validate_structs(Parser(data).parse())
#
#
#def tst(x):
#    print("=== TEST FOR <{0}> === ".format(x))
#    g =  Lexer("").split_word(x)
#    for i in g:
#        print (i)
#
#x = dbg_parser(data)
#for i in x:
#    print i
