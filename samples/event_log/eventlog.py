import windows
import windows.generated_def as gdef

evtlogmgr = windows.system.event_log
print("Event log Manager is: {0}".format(evtlogmgr))
print("They are <{0}> channels".format(len(list(evtlogmgr.channels))))
print("They are <{0}> publishers".format(len(list(evtlogmgr.publishers))))


FIREWALL_CHANNEL = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
print("Openning channel <{0}>".format(FIREWALL_CHANNEL))
evtchan = evtlogmgr[FIREWALL_CHANNEL]
print("Channel is {0}".format(evtchan))
# Note that `evtchan.events` is an alias for `evtchan.query().all()`
print("The channel contains <{0}> events".format(len(evtchan.events)))

print("")
EVT_QUERY = "Event/EventData[Data='C:\\WINDOWS\\System32\\svchost.exe'] and Event/System[EventID=2006]"
print("""Querying "{0}">""".format(EVT_QUERY))
query = evtchan.query(EVT_QUERY)
print("Query is {0}".format(query))
event_list = list(query)
print("List contains {0} event".format(len(event_list)))
event = event_list[0]

print("")
print("First event is {0}".format(event))
print("System values:")
print(" * ID: {0}".format(event.id))
print(" * version: {0}".format(event.version))
print(" * level: {0}".format(event.level))
print(" * opcode: {0}".format(event.opcode))
print(" * time_created: {0}".format(event.time_created))
print(" * ID: {0}".format(event.id))

print("Event specific values:")
for name, value in event.data.items():
    print(" * <{0}> -> <{1}>".format(name, value))

print("")
evtmeta =  event.metadata
print("Event metadata is {0}".format(evtmeta))
print(" * id : {0}".format(evtmeta.id))
print(" * channel_id : {0}".format(evtmeta.channel_id))
print(" * message_id : {0}".format(evtmeta.message_id))
print(" * event_data : {0}".format(evtmeta.event_data))
print(" * EventData template :\n{0}".format(evtmeta.template.replace("\r\n", "\n")))


print("")
print("Exploring complex Evt types:")

print("Channel is still {0}".format(evtchan))
print("Channel config is {0}".format(evtchan.config))
publisher = evtchan.config.publisher
print("Channel publisher is {0}".format(publisher))
print("Channel publisher metadata is {0}".format(publisher.metadata))

print("Publisher's channels are:")
for chan in publisher.metadata.channels:
    print(" * {0}".format(chan))

print("Some publisher's event metadata are:")
for evtmeta in list(publisher.metadata.events_metadata)[:3]:
    print(" * {0}: id={1}".format(evtmeta, evtmeta.id))
