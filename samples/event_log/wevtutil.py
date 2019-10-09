import os
import re
import sys
import xml
import ctypes
import struct
import pickle
import logging
import binascii

from io import BytesIO
from collections import namedtuple

# PythonForWindows
import windows
import windows.generated_def as gdef
from windows.winobject import event_log

""" ParsedElement : This represent a deserialized element for the EventRecord user data, using the xml template associated with the event. """
ParsedElement = namedtuple('ParsedElement', 'index, name, value, format')

class RealtimeEventLoggerBase(object):
    """ Virtual class, used mainly to inject the instance in the EventRecord's context """

    def __init__(self):
        self.etw_trace = None

    def start_process_trace(self):
        """ """

        # Blocking call here, you can't do anything anymore except killing the trace
        self.etw_trace.process(RealtimeEventLogger.callback, context = self)

    @staticmethod
    def callback(event):
        """ Custom callback for listening to ETW events and process them. """
        self = event.context
        self.process_event(event)


    def process_event(self, event):
        raise NotImplementedError("You should implement this method in a subclass !")



class RealtimeEventLogger(RealtimeEventLoggerBase):
    """ Custom reimplementation of a event logger. """

    def __init__(self, trace_name, publisher = None):
        super(RealtimeEventLogger, self).__init__()

        # Open ETW publisher
        self.publisher = None
        self.publisher_name = publisher
        self.publisher_guid = None

        if self.publisher_name:
            manager = event_log.EvtlogManager()
            self.publisher = manager.open_publisher(self.publisher_name)
            self.publisher_guid = self.publisher.metadata.guid
            logging.debug("publisher guid : %s" % self.publisher_guid.to_string())

        # ETW trace
        self.any_keywords = 0
        self.etw_trace_name = trace_name

    def setup_trace(self):

        # Collecting all keywords for listening to events to
        event_keywords = set(map(lambda event_metadata: event_metadata.keyword, self.publisher.metadata.events_metadata))
        self.any_keywords = 0x00
        for keyword in list(event_keywords):
            self.any_keywords |= keyword

        logging.debug("events KeywordsAny : 0x%x" % self.any_keywords)
       

        # Create a custom realtime ETW trace for printing out events
        self.etw_trace = windows.system.etw.open_trace(self.etw_trace_name)


    def start_trace(self):

        self.etw_trace.start()

        # We can't configure etw trace if it's not started previously
        self.etw_trace.enable_ex(
            self.publisher_guid.to_string(), 
            flags=0, 
            level=0xff, 
            any_keyword=self.any_keywords
        )

        self.start_process_trace()

    def stop_trace(self):
        # No way to stop it from python :(
        os.system("logman -ets stop %s" %  self.etw_trace_name)

    def process_event(self, event):
        """ Custom callback for listening to ETW events and parse them correctly. """

        try:
            if event.guid == self.publisher.metadata.guid:

                # Check this is an event we can parse
                event_metadata = self.lookup_event_metadata(self.publisher, event.id)
                if not event_metadata:
                    return

                logging.debug("recv event user data: %s" % event.user_data)
                logging.debug("recv xml template : %s" % event_metadata.template)

                # Deserialize event.user_data based on the event_metadata xml template
                message_data = event.user_data
                message_params = self.parse_user_data(event_metadata.template, message_data)

                logging.debug("message params : %s" %  message_params)

                # "sprintf" the message using the event format message as well as the deserialized elements
                template_message = self.publisher.metadata.message(event_metadata.message_id)
                event_message = self.format_event_log_message(template_message, message_params)
                
                print(event_message)

        except Exception as unke:
            print("Unhandled exception in Evtlogger.process_event : %s" % unke)
            sys.exit(0)  # Exiting on unknown error, since this is the only way to have some control
        finally:
            pass

    def parse_unicode_string(self, stream):
        """ Deserialize a wide string """

        uni_string = b""
        while True:
            unicode_byte = stream.read(2)

            if unicode_byte == b"\x00\x00":
                break

            uni_string += unicode_byte

        return uni_string.decode("utf-16")

    def parse_element(self, in_type, stream, length = None):

        # Types definis dans les templates
        # https://docs.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-inputtype-complextype
        if in_type == "win:UnicodeString":
            value = self.parse_unicode_string(stream)
        elif in_type == "win:UInt8":
            value = struct.unpack("B", stream.read(1))[0]
        elif in_type == "win:UInt32":
            value = struct.unpack("I", stream.read(4))[0]
        elif in_type == "win:HexInt32":
            value = struct.unpack("I", stream.read(4))[0]
        elif in_type == "xs:unsignedLong":
            value = struct.unpack("I", stream.read(4))[0]
        elif in_type == "win:UInt64":
            value = struct.unpack("Q", stream.read(8))[0]
        elif in_type == "win:Pointer":
            value = struct.unpack("Q", stream.read(8))[0]
        elif in_type == "win:Binary":
            if not length:
                raise ValueError(" param_in_type (%s) cannot be used with a null length value" % in_type)
            
            # TODO : we should return the raw bytes buffer, since get_param_str_format is too crude 
            #        to properly display win:SocketAddress parameters
            value = binascii.hexlify(stream.read(length)) 
        elif in_type == "win:GUID":
            guid_data = struct.unpack("IHHBBBBBBBB", stream.read(16))
            value = gdef.GUID.from_raw(*guid_data).to_string()
        else:
            raise ValueError("unrecognized param_in_type : %s" % in_type)

        return value

    def get_param_str_format(self, param_out_type):
        PYTHON_FORMAT_DICT = {
            "xs:unsignedByte" : "02x",
            "xs:unsignedInt" : "d",
            "xs:unsignedLong" : "d",
            "win:ErrorCode"  : "x",
            "win:HexInt64"   : "0x08x",
            "win:HexInt32"   : "0x04x",
            "xs:string"      : "s",
            "win:SocketAddress" : "s" # TODO
        }

        if param_out_type not in PYTHON_FORMAT_DICT:
            raise ValueError("unrecognized out param : %s" %  param_out_type)

        return PYTHON_FORMAT_DICT[param_out_type]

    def parse_user_data(self, template, data):
        """ 
        Deserialize event.user_data based on the associated publisher's template.
        Return a list of ParsedElement(Name:string, Value:py_object, Type:py_type).
        """
            
        # xml.dom.minidom.parseString raise an error on parseString() if the xml template is empty
        if not len(template):
            return []

        stream = BytesIO(data)
        xmltemplate = xml.dom.minidom.parseString(template)
        
        params = []
        context = {} # saving parsed items for "count" elements

        # xmltemplate.getElementsByTagName("data") return data node within <struct> decl, so we can't use it
        direct_data_nodes = filter(lambda n: n.nodeType == 1 and n.tagName == "data", xmltemplate.childNodes[0].childNodes)

        for (i,param_data) in enumerate(direct_data_nodes):

            param_name = param_data.attributes["name"].value
            param_in_type = param_data.attributes["inType"].value
            param_out_type = param_data.attributes["outType"].value

            # Some param are repeating, and "count" refers to the variable holding the number of repetitions
            param_count = param_data.attributes.get("count", None)
            if param_count != None:
                param_count = context[param_count.value] # must be already set

            # Some param (win:Binary) have a length attribute
            param_length = param_data.attributes.get("length", None)
            if param_length != None:
                param_length = context[param_length.value] # must be already set
            

            # Parse element
            if param_count != None:

                # ignoring element with value count of 0
                if param_count == 0:
                    continue

                value = [ self.parse_element(param_in_type, stream, param_length) for c in range(param_count) ]
            else:
                value = self.parse_element(param_in_type, stream, param_length)

            # Get python string formating 
            format_type = self.get_param_str_format(param_out_type)

            context[param_name] = value

            logging.debug(ParsedElement(i, param_name,value, format_type))
            params.append(ParsedElement(i, param_name,value, format_type))

        return params

    def lookup_event_metadata(self, publisher, event_id):
        matching_events_metadata = list(filter(lambda event_meta: event_meta.id == event_id, publisher.metadata.events_metadata))
        
        if not len(matching_events_metadata):
            return None

        if len(matching_events_metadata) > 1:
            return None

        return matching_events_metadata[0]

    def format_event_log_message(self, template, event_args):
        
        py_template = ""
        last_span = (0,0)
        
        # Convert message template to python string formating
        # e.g. : "ParseError: HResult: %1, Error: %2." into "ParseError: HResult: {arg0:x}, Error: {arg1:d}."
        pattern = re.compile(r"%(\d)")
        for match in re.finditer(pattern, template):
        
            arg_id = int(match.groups()[0]) - 1 # event's template message index params from 1 to N, wtf
            span = match.span()
            str_format = ""
        
            str_format = "{a%d:%s}" % (arg_id, event_args[arg_id].format)
        
            py_template += template[last_span[1]:span[0]] + str_format
            last_span = span
        
        py_template += template[last_span[1]:]
        
        logging.debug(py_template)
        
        # string formating using Python .format()
        events_kwargs =  {"a%d" % (x.index) : x.value for x in event_args}
        logging.debug(events_kwargs)
        message = py_template.format(**events_kwargs)
        logging.debug(message)
        return message



def get_message(publisher_metadata, message_id, get_str_message):
    """ if --gm is set, try to return the str message associated. If not, return the raw value id """
    if not get_str_message:
        return "%d" % message_id

    try:
        return publisher_metadata.message(message_id)
    except WindowsError as e:
        if e.winerror != gdef.ERROR_INVALID_PARAMETER:
            raise
        return ""

def format_channel_metadata(publisher_metadata, channel_metadata, args):
    """ Str formating channel metadata """
    return "\n".join([
        "  channel:",
        "    name: {channel.name:s}",
        "    id: {channel.id:d}",
        "    flags: {channel.flags:d}",
        "    message: {channel_message:s}",
    ]).format(
        channel=channel_metadata, 
        channel_message=get_message(publisher_metadata, channel_metadata.message_id, args.gm)
    )

def format_level_metadata(publisher_metadata, level_metadata, args):
    """ Str formating level metadata """
    return "\n".join([
        "  level:",
        "    name: {level.name:s}",
        "    value: {level.value:d}",
        "    message: {level_message:s}", 
    ]).format(
        level=level_metadata, 
        level_message=get_message(publisher_metadata, level_metadata.message_id, args.gm)
    )

def format_opcode_metadata(publisher_metadata, opcode_metadata, args):
    """ Str formating opcode metadata """
    return "\n".join([
        "  opcode:",
        "    name: {opcode.name:s}",
        "    value: {opcode.value:d}",
        #"      task: {opcode.task:d}",          # TODO
        #"      opcode: {opcode.task_value:d}",  # TODO
        "    message: {opcode_message:s}", 
    ]).format(
        opcode=opcode_metadata, 
        opcode_message=get_message(publisher_metadata, opcode_metadata.message_id, args.gm)
    )

def format_task_metadata(publisher_metadata, task_metadata, args):
    """ Str formating task metadata """
    return "\n".join([
        "  task:",
        "    name: {task.name:s}",
        "    value: {task.value:d}",
        "    eventGUID: {task.event_guid:s}",   
        "    message: {task_message:s}",        
    ]).format(
        task=task_metadata, 
        task_message=get_message(publisher_metadata, task_metadata.message_id, args.gm)
    )

def format_keyword_metadata(publisher_metadata, keyword_metadata, args):
    """ Str formating keyword metadata """
    return "\n".join([
        "  keyword:",
        "    name: {keyword.name:s}",
        "    mask: {keyword.value:x}",
        "    message: {keyword_message:s}",  
    ]).format(
        keyword=keyword_metadata, 
        keyword_message=get_message(publisher_metadata, keyword_metadata.message_id, args.gm)
    )

def format_event_metadata(publisher_metadata, event_metadata, args):
    """ Str formating keyword metadata """
    return "\n".join([
         "  event:",
        "    value: {event.id:d}",
        "    version: {event.version:d}",
        "    opcode: {event.opcode:d}",
        "    channel: {event.channel_id:d}",
        "    level: {event.level:d}",
        "    task: {event.task:d}",
        "    keywords: 0x{event.keyword:016x}",
        "    message: {event_message:s}" 
    ]).format(
        event=event_metadata, 
        event_message=get_message(publisher_metadata, event_metadata.message_id, args.gm)
    )

def enum_publishers(args):
    """ enum-publishers verb implementation """
    manager = event_log.EvtlogManager()
    for publisher in sorted(list(manager.publishers), key=lambda pub:pub.name.lower()):    
        print(publisher.name)        

def get_publisher(args):
    """ get-publisher verb implementation """
    
    manager = event_log.EvtlogManager()
    publisher = manager.open_publisher(args.publisher_name)

    channels_info = "\n".join(map(lambda c: format_channel_metadata(publisher.metadata, c, args), publisher.metadata.channels_metadata))
    levels_info = "\n".join(map(lambda l: format_level_metadata(publisher.metadata, l, args), publisher.metadata.levels_metadata))
    opcodes_info = "\n".join(map(lambda o: format_opcode_metadata(publisher.metadata, o, args), publisher.metadata.opcodes_metadata))
    tasks_info = "\n".join(map(lambda t: format_task_metadata(publisher.metadata, t, args), publisher.metadata.tasks_metadata))
    keywords_info = "\n".join(map(lambda k: format_keyword_metadata(publisher.metadata, k, args), publisher.metadata.keywords_metadata))
    events_info = "\n".join(map(lambda e: format_event_metadata(publisher.metadata, e, args), publisher.metadata.events_metadata))

    publisher_infos = "\n".join([
        "name: {pub_name:s}",
        "guid: {pub_guid:s}",
    ]).format(
        pub_name=publisher.name,
        pub_guid=publisher.metadata.guid.to_string(),
    )

    if publisher.metadata.message_resource_filepath != None:
        publisher_infos += "\n"
        publisher_infos += "resourceFileName: {:s}".format(publisher.metadata.message_resource_filepath)
    if publisher.metadata.message_parameter_filepath != None:
        publisher_infos += "\n"
        publisher_infos += "parameterFileName: {:s}".format(publisher.metadata.message_parameter_filepath)
    if publisher.metadata.message_filepath != None:
        publisher_infos += "\n"
        publisher_infos += "messageFileName: {:s}".format(publisher.metadata.message_filepath)

    publisher_infos += "\n"
    publisher_infos += "message: {:s}".format(get_message(publisher.metadata, publisher.metadata.message_id, args.gm))

    # Channels
    publisher_infos += "\n"
    publisher_infos += "channels:"
    if channels_info != "":
        publisher_infos += "\n"
        publisher_infos += channels_info

    # Levels
    publisher_infos += "\n"
    publisher_infos += "levels:"
    if levels_info != "":
        publisher_infos += "\n"
        publisher_infos += levels_info

    # Opcodes
    publisher_infos += "\n"
    publisher_infos += "opcodes:"
    if opcodes_info != "":
        publisher_infos += "\n"
        publisher_infos += opcodes_info

    # Tasks
    publisher_infos += "\n"
    publisher_infos += "tasks:"
    if tasks_info != "":
        publisher_infos += "\n"
        publisher_infos += tasks_info

    # Keywords
    publisher_infos += "\n"
    publisher_infos += "keywords:"
    if keywords_info != "":
        publisher_infos += "\n"
        publisher_infos += keywords_info

    # Events
    if args.ge:
        publisher_infos += "\n"
        publisher_infos += "events:"
        if events_info != "":
            publisher_infos += "\n"
            publisher_infos += events_info

    publisher_infos += "\n"
    print(publisher_infos)
    

def main(args):

    if args.action == "enum-publishers":
        enum_publishers(args)
    elif args.action == "get-publisher":
        get_publisher(args)
    elif args.action == "start-trace":
        evl = RealtimeEventLogger(args.etw_name, publisher = args.publisher_name)
        evl.setup_trace()
        evl.start_trace()
    elif args.action == "stop-trace":
        evl = RealtimeEventLogger(args.etw_name)
        evl.stop_trace()
    else:
        raise NotImplementedError("Unknown action : %s" % args.action)

if __name__ == '__main__':

    import argparse
    parser = argparse.ArgumentParser("wevtutil script reimplementation using PythonForWindows")
    parser.add_argument("-v", "--verbose", action="store_true", help="active verbose logging")
    action_parsers = parser.add_subparsers(dest="action", help="subparsers for action specific arguments")

    # we can't express shorthands easily like ep for enum-publishers since only Python3's argparse surpport parser "aliases"
    enum_publishers_parser = action_parsers.add_parser("enum-publishers", help="enum-publishers verb")
    
    get_publisher_parser = action_parsers.add_parser("get-publisher", help="get-publisher verb")
    get_publisher_parser.add_argument("publisher_name", type=str, help="registered publisher name")
    get_publisher_parser.add_argument("--ge", action="store_true", help="get event metadata")
    get_publisher_parser.add_argument("--gm", action="store_true", help="get message name instead of raw id")
    # get_publisher_parser.add_argument("--f", type=str, help="format")                                           # TODO
    # get_publisher_parser.add_argument("--im", "--install-manifest", type=str, help="install manifest ???")      # TODO


    # Not a wevutil command, but something nice to have ;p
    start_trace_parser = action_parsers.add_parser("start-trace", help="start a realtime ETW trace")
    start_trace_parser.add_argument("etw_name", type=str, help="ETW trace name")
    start_trace_parser.add_argument("publisher_name", type=str, help="registered publisher name")

    stop_trace_parser = action_parsers.add_parser("stop-trace", help="start a realtime ETW trace")
    stop_trace_parser.add_argument("etw_name", type=str, help="ETW trace name")


    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    main(args)


