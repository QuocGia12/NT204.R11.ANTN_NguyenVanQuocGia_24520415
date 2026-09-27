import json 
from typing import TextIO 
# TextIO: object used for reading or writing text

import pyshark 

from pathlib import Path
from .parser import PacketParser



def write_event(output: TextIO, parsed_packet: dict): 
    output.write(json.dumps(parsed_packet) + "\n") # json.dumps(parsed_packet): convert parsed_packet from python dict to JSONL 
    output.flush() # force python to immediately write to output instead of waiting more buffer data 

parser = PacketParser()

# mode importing pcap file 
def process_pcap(pcap_file: Path, output_packet: TextIO, output_application: TextIO): 
    capture = pyshark.FileCapture(
        input_file=str(pcap_file),
        keep_packets=False, 
        override_prefs={
            "ip.defragment": "TRUE", 
            "ipv6.defragment": "TRUE",
            "tcp.desegment_tcp_streams": "TRUE",
        }
    )

    for packet in capture:  
        parsed_packet = parser.parse(packet)
        write_event(output_packet, parsed_packet["packet"])
        if (parsed_packet["application"]): 
            write_event(output_application, parsed_packet["application"])


# mode live capturing 
def process_interface(interface: str, output_packet: TextIO, output_application: TextIO): 
    capture = pyshark.LiveCapture(
        interface=interface, 
        # keep_packets=False, 
        override_prefs={
            "ip.defragment": "TRUE", 
            "ipv6.defragment": "TRUE",
            "tcp.desegment_tcp_streams": "TRUE",
        }
    )

    for packet in capture.sniff_continuously():
        parsed_packet = parser.parse(packet)
        write_event(output_packet, parsed_packet["packet"])
        if (parsed_packet["application"]): 
            write_event(output_application, parsed_packet["application"])