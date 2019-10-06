import os
import sys
import ctypes

import windows
import windows.generated_def as gdef
from windows.winobject import event_log


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
        level=opcode_metadata, 
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

    manager = event_log.EvtlogManager()
    for publisher in sorted(list(manager.publishers), key=lambda pub:pub.name.lower()):    
        print(publisher.name)        

def get_publisher(args):
    
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

    print(publisher_infos)

    

def main(args):

    if args.action == "enum-publishers":
        enum_publishers(args)

    elif args.action == "get-publisher":
        get_publisher(args)
    else:
        raise NotImplementedError("Unknown action : %s" % args.action)

if __name__ == '__main__':

    import argparse
    parser = argparse.ArgumentParser("wevtutil script reimplementation using PythonForWindows")
    action_parsers = parser.add_subparsers(dest="action", help="subparsers for action specific arguments")

    # we can't express shorthands easily like ep for enum-publishers since only Python3's argparse surpport parser "aliases"
    enum_publishers_parser = action_parsers.add_parser("enum-publishers", help="enum-publishers verb")
    
    get_publisher_parser = action_parsers.add_parser("get-publisher", help="get-publisher verb")
    get_publisher_parser.add_argument("publisher_name", type=str, help="registered publisher name")
    get_publisher_parser.add_argument("--ge", action="store_true", help="get event metadata")
    get_publisher_parser.add_argument("--gm", action="store_true", help="get message name instead of raw id")
    # get_publisher_parser.add_argument("--f", type=str, help="format")                                           # TODO
    # get_publisher_parser.add_argument("--im", "--install-manifest", type=str, help="install manifest ???")      # TODO


    args = parser.parse_args()
    main(args)


