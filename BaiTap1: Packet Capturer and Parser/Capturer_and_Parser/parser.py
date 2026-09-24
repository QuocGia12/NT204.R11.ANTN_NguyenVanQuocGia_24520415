from scapy.packet import Packet, Raw
from typing import Any 
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS 
from scapy.layers.http import HTTPRequest, HTTPResponse 

class PacketParser: 
    def parse(self, packet: Packet): 
        parsed_packet = self.base_parsed_packet(packet)


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
            "layer3_protocol":  packet[IP].proto, # protocol of L3 layer, not network layer (1: ICMP, 6: TCP, 17: UDP)
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
    elif ICMP in packet: # only parse some valuable fields of ICMP 
        return {
            "protocol": "ICMP", 
            "type": packet[ICMP].type,
            "code": packet[ICMP].code,
            "check_sum": packet[ICMP].chksum,
        }
    else: 
        return {
            "protocol": "UNKNOWN"
        }

def parse_application(packet: Packet) -> dict[str, Any]:  
    if HTTPRequest in packet: 
        req = packet[HTTPRequest]

        return {
            "method": convert_bytes_to_string(req.Method),
            "path": convert_bytes_to_string(req.Path),
            "http_version": convert_bytes_to_string(req.Http_Version),
            "accept": convert_bytes_to_string(req.Accept),
            "accept_encoding": convert_bytes_to_string(req.Accept_Encoding),
            "accept_language": convert_bytes_to_string(req.Accept_Language),
            "authorization": convert_bytes_to_string(req.Authorization),
            "cache_control": convert_bytes_to_string(req.Cache_Control),
            "connection": convert_bytes_to_string(req.Connection),
            "content_length": convert_bytes_to_string(req.Content_Length),
            "content_type": convert_bytes_to_string(req.Content_Type),
            "cookie": convert_bytes_to_string(req.Cookie),
            "host": convert_bytes_to_string(req.Host),
            "if_modified_since": convert_bytes_to_string(req.If_Modified_Since),
            "if_none_match": convert_bytes_to_string(req.If_None_Match),
            "origin": convert_bytes_to_string(req.Origin),
            "referer": convert_bytes_to_string(req.Referer),
            "user_agent": convert_bytes_to_string(req.User_Agent),
            "unknown_headers": req.Unknown_Headers,
        }
    elif HTTPResponse in packet: 
        res = packet[HTTPResponse]

        return {
            "http_version": convert_bytes_to_string(res.Http_Version),
            "status_code": convert_bytes_to_string(res.Status_Code),
            "reason_phrase": convert_bytes_to_string(res.Reason_Phrase),

            "accept_ranges": convert_bytes_to_string(res.Accept_Ranges),
            "age": convert_bytes_to_string(res.Age),
            "allow": convert_bytes_to_string(res.Allow),
            "cache_control": convert_bytes_to_string(res.Cache_Control),
            "connection": convert_bytes_to_string(res.Connection),
            "content_encoding": convert_bytes_to_string(res.Content_Encoding),
            "content_language": convert_bytes_to_string(res.Content_Language),
            "content_length": convert_bytes_to_string(res.Content_Length),
            "content_location": convert_bytes_to_string(res.Content_Location),
            "content_md5": convert_bytes_to_string(res.Content_MD5),
            "content_range": convert_bytes_to_string(res.Content_Range),
            "content_type": convert_bytes_to_string(res.Content_Type),
            "date": convert_bytes_to_string(res.Date),
            "etag": convert_bytes_to_string(res.ETag),
            "expires": convert_bytes_to_string(res.Expires),
            "last_modified": convert_bytes_to_string(res.Last_Modified),
            "location": convert_bytes_to_string(res.Location),
            "pragma": convert_bytes_to_string(res.Pragma),
            "retry_after": convert_bytes_to_string(res.Retry_After),
            "server": convert_bytes_to_string(res.Server),
            "set_cookie": convert_bytes_to_string(res.Set_Cookie),
            "vary": convert_bytes_to_string(res.Vary),
            "www_authenticate": convert_bytes_to_string(res.WWW_Authenticate),

            "unknown_headers": res.Unknown_Headers,
        }
    elif DNS in packet: 
        return {

        }
    elif Raw in packet: 
        # process 
        return {
            "Raw": convert_bytes_to_string(packet[Raw].load)
        }
    else: 
        return {
            "protocol": "Unknown"
        }
    

def convert_bytes_to_string(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value