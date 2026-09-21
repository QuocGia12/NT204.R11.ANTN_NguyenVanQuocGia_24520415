import json 
from typing import TextIO 
# TextIO: object used for reading or writing text

from scapy.all import Pcapreader 
from scapy.packet import Packet 
# Pcapreader: read pcapfile and return list Packet 
# Packet: Packet object 

from .parser import PacketParser 


def write_event(output: TextIO, parsed_packet: dict): 
    output.write(json.dumps(parsed_packet) + "\n") # json.dumps(parsed_packet): convert parsed_packet from python dict to JSONL 
    output.flush() # force python to immediately write to output instead of waiting more buffer data 

parser = PacketParser()

# mode importing pcap file 
def process_pcap(pcap_file: Path, output: Path): 
    with open(str(output), "w") as file: 
        with Pcapreader(str(pcap_file)) as list_packets: 
            for packet in list_packets: 
                parsed_packet = parser.parse(packet)
            write_event(file, parsed_packet)               


# mode live capturing 
def process_interface(interface: string, output: Path): 
    # with open 