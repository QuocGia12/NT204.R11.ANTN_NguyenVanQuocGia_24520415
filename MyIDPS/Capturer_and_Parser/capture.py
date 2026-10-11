import json 
from typing import TextIO 
# TextIO: object used for reading or writing text

import pyshark 

from pathlib import Path
from .parser import PacketParser
from .flow import FlowTracker 



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

    output.write(json.dumps(filtered_packet) + "\n")
    output.flush()


parser = PacketParser()
tracker = FlowTracker()

def write_flow_table(output_flow: TextIO, tracker: FlowTracker):
    for flow in tracker.snapshot():
        write_event(output_flow, flow)

# mode importing pcap file 
def process_pcap(pcap_file: Path, output_packet: TextIO, output_application: TextIO, output_flow: TextIO): 
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
            flow_id = tracker.observe(packet)
            parsed_packet = parser.parse(packet, flow_id)
            write_event(output_packet, parsed_packet["packet"])
            if (parsed_packet["application"]): 
                write_event(output_application, parsed_packet["application"])
    finally: 
        capture.close()
        write_flow_table(output_flow, tracker)


# mode live capturing 
def process_interface(interface: str, output_packet: TextIO, output_application: TextIO, output_flow: TextIO): 
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
            flow_id = tracker.observe(packet)
            parsed_packet = parser.parse(packet, flow_id)
            write_event(output_packet, parsed_packet["packet"])
            if (parsed_packet["application"]): 
                write_event(output_application, parsed_packet["application"])
    except KeyboardInterupt:
        pass 
    finally: 
        capture.close()
        write_flow_table(output_flow, tracker)