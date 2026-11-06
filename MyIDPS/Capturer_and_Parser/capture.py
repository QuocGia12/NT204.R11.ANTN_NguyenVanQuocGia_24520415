import json 
from typing import TextIO 
# TextIO: object used for reading or writing text

from pathlib import Path
from .parser import PacketParser
from .flow import FlowTracker
try:
    from ..Core_Engine import RuleMatcher, RuleRepository
except ImportError:  # Support running main.py directly from the MyIDPS folder.
    from Core_Engine import RuleMatcher, RuleRepository



def remove_none(data):
    if isinstance(data, dict):
        return {
            key: remove_none(value)
            for key, value in data.items()
            if value is not None or key == "flow_id"
        }

    elif isinstance(data, list):
        return [
            remove_none(item)
            for item in data
            if item is not None
        ]

    return data


def write_event(output: TextIO, parsed_packet: dict): # write parsed_packet into output file 
    filtered_packet = remove_none(parsed_packet) # remove none value from parsed_packet 

    # output.write(json.dumps(filtered_packet) + "\n")
    output.write(json.dumps(filtered_packet, ensure_ascii=False) + "\n")
    output.flush()


parser = PacketParser()
tracker = FlowTracker()

def write_flow_table(output_flow: TextIO, tracker: FlowTracker):
    for flow in tracker.snapshot():
        write_event(output_flow, flow)

def process_packet(
    packet,
    output_packet: TextIO,
    output_application: TextIO,
    output_detection: TextIO | None = None,
    repository: RuleRepository | None = None,
    matcher: RuleMatcher | None = None,
) -> None:
    """Parse one packet, preserve legacy logs and optionally write alerts."""
    flow_context = tracker.observe(packet)
    parsed_packet = parser.parse(packet, flow_context)
    write_event(output_packet, parsed_packet["packet"])
    if parsed_packet["application"]:
        write_event(output_application, parsed_packet["application"])

    if output_detection is None or repository is None:
        return

    packet_context = parsed_packet["context"]
    rule_matcher = matcher or RuleMatcher()
    candidate_rules = repository.candidates(packet_context)
    for event in rule_matcher.match_events(packet_context, candidate_rules):
        write_event(output_detection, event.to_dict())


# mode importing pcap file
def process_pcap(
    pcap_file: Path,
    output_packet: TextIO,
    output_application: TextIO,
    output_flow: TextIO,
    output_detection: TextIO | None = None,
    repository: RuleRepository | None = None,
    matcher: RuleMatcher | None = None,
):
    # PyShark is only needed when an actual capture is started.  Keeping this
    # import local lets the parser, rule engine and CLI help work without the
    # optional capture dependency being installed.
    import pyshark

    capture = pyshark.FileCapture(
        input_file=str(pcap_file),
        keep_packets=False, 
        override_prefs={
            "ip.defragment": "TRUE", 
            "ipv6.defragment": "TRUE",
            "tcp.desegment_tcp_streams": "TRUE",
        }
    )
    try: 
        for packet in capture:  
            process_packet(
                packet,
                output_packet=output_packet,
                output_application=output_application,
                output_detection=output_detection,
                repository=repository,
                matcher=matcher,
            )
    finally: 
        capture.close()
        write_flow_table(output_flow, tracker)


# mode live capturing 
def process_interface(
    interface: str,
    output_packet: TextIO,
    output_application: TextIO,
    output_flow: TextIO,
    output_detection: TextIO | None = None,
    repository: RuleRepository | None = None,
    matcher: RuleMatcher | None = None,
):
    import pyshark

    capture = pyshark.LiveCapture(
        interface=interface, 
        # keep_packets=False, 
        override_prefs={
            "ip.defragment": "TRUE", 
            "ipv6.defragment": "TRUE",
            "tcp.desegment_tcp_streams": "TRUE",
        }
    )

    try: 
        for packet in capture.sniff_continuously():
            process_packet(
                packet,
                output_packet=output_packet,
                output_application=output_application,
                output_detection=output_detection,
                repository=repository,
                matcher=matcher,
            )
    except KeyboardInterrupt:
        pass 
    finally: 
        capture.close()
        write_flow_table(output_flow, tracker)
