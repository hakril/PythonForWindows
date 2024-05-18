import os
import sys
import logging
import inspect

options = {'active': False, 'cats': None}
# options = {'active': True, 'cats': ["HANDLE"]}


def get_stack_func_name(lvl):
    info = inspect.stack()[lvl]
    return info[0], info[3]


def do_dbgprint(msg, type=None):
    if ("ALL" in options['cats']) or type.upper() in options['cats']:
        frame, func = get_stack_func_name(2)
        logger = logging.getLogger(frame.f_globals['__name__'] + ":" + func)
        logger.debug(msg)


def do_nothing(*args, **kwargs):
    return None


def parse_option(s):
    if s[0] == "=":
        s = s[1:]
    if s:
        cats = [x.upper().strip() for x in s.split('-')]
        options['cats'] = cats

    formt = 'DBG|%(name)s|%(message)s'
    logging.basicConfig(format=formt, level=logging.DEBUG)

try:
    if 'DBGPRINT' in os.environ:
        parse_option(os.environ['DBGPRINT'])
        dbgprint = do_dbgprint
    elif any([opt.startswith("--DBGPRINT") for opt in sys.argv]):
        dbgprint = do_dbgprint
        option_str = [opt for opt in sys.argv if opt.startswith("--DBGPRINT")][0]
        parse_option(option_str[len('--DBGPRINT'):])
    elif options["active"]:
        formt = 'DBG|%(name)s|%(message)s'
        logging.basicConfig(format=formt, level=logging.DEBUG)
        dbgprint = do_dbgprint
    else:
        dbgprint = do_nothing
except Exception as e:
    dbgprint = do_nothing
    print("dbgprint Error: {0}({1})".format(type(e), e))
    x = type(e), e
