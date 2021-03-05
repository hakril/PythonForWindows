import sys
import windows

# target = int(sys.argv[1])

import argparse

parser = argparse.ArgumentParser(prog=__file__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('--channel', nargs=1)
parser.add_argument('--publisher', nargs=1)
parser.add_argument('--verbose', action="store_true")
parser.add_argument('--evtdata', action="store_true")
parser.add_argument('--list-channels', action="store_true")
parser.add_argument('--list-publishers', action="store_true")
parser.add_argument('evtid', nargs="?", type=int)
args = parser.parse_args()
print(args)

for publisher in windows.system.event_log.publishers:
    if args.publisher and args.publisher[0] not in publisher.name:
        continue

    if args.list_publishers:
        print(publisher)
        continue

    try:
        channels = publisher.metadata.channel_name_by_id
    except WindowsError as e:
        if args.verbose:
            print(publisher, e)
        continue



    if args.list_channels:
        publisher_printed = False
        for chan in channels.values():
            if args.channel and  args.channel[0] not in chan:
                continue
            if not publisher_printed:
                print(publisher)
                publisher_printed = True
            print(" * {0}".format(chan))
        continue


    if args.channel:
        channels = {k:v for k,v in channels.items() if args.channel[0] in v}

    try:
        eventsmeta = publisher.metadata.events_metadata
    except WindowsError as e:
        if args.verbose:
            print(publisher, e)
        continue

    match_events = {k: [] for k in channels}
    match_events[0] = []
    try:
        for eventmeta in eventsmeta:
            if args.evtid and args.evtid != eventmeta.id:
                continue
            if eventmeta.channel_id in match_events:
                match_events[eventmeta.channel_id].append(eventmeta)
    except WindowsError as e:
        if args.verbose:
            print(publisher, e)
        continue

    for channel_id in match_events:
        # if args.channel: print channel anyway
        if (not args.channel) and not match_events[channel_id]:
            continue
        if channel_id == 0:
            print("<Undefined channel> of {0}".format(publisher))
        else:
            print(channels[channel_id])
        for eventsmeta in match_events[channel_id]:
            try:
                msg = publisher.metadata.message(eventsmeta.message_id)
            except WindowsError as e:
                msg = ""

            print("  * {0} <{1!r}>".format(eventsmeta.id, msg))
            if args.evtdata:
                for evtdata in eventsmeta.event_data:
                    print("    * {0} ({1})".format(evtdata["name"], evtdata["outType"]))

