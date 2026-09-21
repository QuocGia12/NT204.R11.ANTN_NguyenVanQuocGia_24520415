import json 
from typing import TextIO 
# TextIO: object used for reading or writing text

from scapy.all import PcapReader 
from scapy.packet import Packet 
from pathlib import Path
# PcapReader: read pcapfile and return list Packet 
# Packet: Packet object 

from .parser import PacketParser 


def write_event(output: TextIO, parsed_packet: dict): 
    output.write(json.dumps(parsed_packet) + "\n") # json.dumps(parsed_packet): convert parsed_packet from python dict to JSONL 
    output.flush() # force python to immediately write to output instead of waiting more buffer data 

parser = PacketParser()

# mode importing pcap file 
def process_pcap(pcap_file: Path, output: TextIO): 
    with PcapReader(str(pcap_file)) as list_packets: 
        for packet in list_packets: 
            parsed_packet = parser.parse(packet)
            write_event(output, parsed_packet)               


# mode live capturing 
def process_interface(interface: str, output: Path): 
    print("chua implemnet")