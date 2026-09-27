import pyshark
import json

class PacketParser: 
    def parse(self, packet): 
        # test 
        parsed_packet = self.base_parsed_packet(packet)

        # process packet 
        parsed_packet["packet"]["number"] = to_json_safe(packet.number)
        parsed_packet["packet"]["sniff_time"] = to_json_safe(packet.sniff_time)
        if "IP" in packet or "IPV6" in packet: 
            parsed_packet["packet"]["network"] = parse_network(packet)
        else: 
            parsed_packet["packet"]["network"]["protocol"] = "UNKNOWN"

        if "TCP" in packet or "UDP" in packet: 
            parsed_packet["packet"]["transport"] = parse_transport(packet)
            parsed_packet["packet"]["payload"] = parse_transport_payload(packet).decode("utf-8", errors="replace")
        else: 
            parsed_packet["packet"]["transport"]["protocol"] = "UNKNOWN"
            parsed_packet["packet"]["payload"] = "UNKNOWN"

        # process application if applicable
        # not yet implemented

        return parsed_packet
    
    def base_parsed_packet(self, packet): 
        return {
            "packet": {
            }, 
            "application": {
            }
        }
    

def parse_transport_payload(packet):
    if "TCP" in packet:
        payload = getattr(packet.tcp, "payload", None)

    elif "UDP" in packet:
        payload = getattr(packet.udp, "payload", None)

    else:
        return b""

    if not payload:
        return b""

    return bytes.fromhex(payload.replace(":", "")) # return bytes 

def parse_network(packet): 
    if "IP" in packet:
        ip = packet.ip

        return {
            "version": 4,
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "ttl": getattr(ip, "ttl", None),
            "protocol": getattr(ip, "proto", None),
            "length": getattr(ip, "len", None),
            "id": getattr(ip, "id", None),
            "flags": getattr(ip, "flags", None),
            "fragment_offset": getattr(ip, "frag_offset", None),
        }
    elif "IPV6" in packet:
        ip = packet.ipv6

        return {
            "version": 6,
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "hop_limit": getattr(ip, "hlim", None),
            "next_header": getattr(ip, "nxt", None),
            "payload_length": getattr(ip, "plen", None),
        }

    return None


def parse_transport(packet):
    if "TCP" in packet:
        tcp = packet.tcp

        return {
            "protocol": "TCP",
            "src_port": int(tcp.srcport),
            "dst_port": int(tcp.dstport),
            "seq": int(tcp.seq),
            "ack": int(tcp.ack),
            "flags": tcp.flags,
            "window_size": int(tcp.window_size_value),
            "payload_len": int(tcp.len),
        }

    elif "UDP" in packet:
        udp = packet.udp

        return {
            "protocol": "UDP",
            "src_port": int(udp.srcport),
            "dst_port": int(udp.dstport),
            "length": int(udp.length),
        }

    return None





def to_json_safe(value):
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError, OverflowError):
        return str(value)

# def convert_bytes_to_string(value):
#     if isinstance(value, bytes):
#         return value.decode("utf-8", errors="replace")
#     return value