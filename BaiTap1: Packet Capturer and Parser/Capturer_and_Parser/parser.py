from scapy.packet import Packet, Raw
from typing import Any 
from scapy.layers.inet import IP, TCP, UDP

class PacketParser: 
    def parse(self, packet: Packet): 
        parsed_packet = self.base_parsed_packet(packet)

        # SOLVE UNKNOWN OR MALFORM PACKET 
        # if IP not in packet: 
        #     parsed_packet["network"]["protocol"] = "UNKNOWN"
        #     if TCP in packet: 
        #         parsed_packet["transport"]["protocol"] = "UNKNOWN"

        parsed_packet["network"] = parse_network(packet)
        parsed_packet["transport"] = parse_transport(packet)
        parsed_packet["application"] = parse_application(packet)
        print(parsed_packet)
        return parsed_packet 

    def base_parsed_packet(self, packet): 
        return {
            "network": {}, 
            "transport": {}, 
            "application": {},
        }
    



def parse_network(packet: Packet) -> dict[str, Any]: 
    if IP in packet: 
        return {
            "source_IP": packet[IP].src, 
            "dest_IP":  packet[IP].dst, 
            "ttl":  packet[IP].ttl, 
            "protocol":  packet[IP].proto, 
            "len":  packet[IP].len, 
            "id":  packet[IP].id, 
            "flags":  str(packet[IP].flags), 
            "frag":  packet[IP].frag,  
            "version":  packet[IP].version,  
            "header_len":  packet[IP].ihl,  
            "type_of_service":  packet[IP].tos,  
            "check_sum":  packet[IP].chksum, 
            # "options": packet[IP].options, 
        }
    else: 
        return {
            "protocol": "UNKNOWN"
        }

def parse_transport(packet: Packet) -> dict[str, Any]: 
    if TCP in packet: 
        return {
            "protocol": "TCP",
            "source_port": packet[TCP].sport,
            "dest_port": packet[TCP].dport,
            "seq_number": packet[TCP].seq,
            "ack_number": packet[TCP].ack,
            "header_len": packet[TCP].dataofs,
            "reserved_bits": packet[TCP].reserved,
            "flags": str(packet[TCP].flags),
            "window": packet[TCP].window,
            "check_sum": packet[TCP].chksum,
            "urgent_pointer": packet[TCP].urgptr,
            # "options": packet[TCP].options,

        }
    elif UDP in packet:
        return {
            "protocol": "UDP",
            "soure_port": packet[UDP].sport,
            "dest_port": packet[UDP].dport,
            "len": packet[UDP].len,
            "check_sum": packet[UDP].chksum,
        }
    else: 
        return {
            "protocol": "UNKNOWN"
        }

def parse_application(packet: Packet) -> dict[str, Any]:  
    if Raw in packet: 
        return {
            "raw_data": packet[Raw].load.decode("utf-8", errors="replace")
        }
    else: 
        return {
            "protocol": "UNKNOWN"
        }