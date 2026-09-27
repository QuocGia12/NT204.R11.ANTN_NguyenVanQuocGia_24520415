import pyshark
import json

NON_APPLICATION_LAYERS = {
    "eth", "sll", "sll2", "ip", "ipv6",
    "tcp", "udp", "icmp", "icmpv6",
    "arp", "vlan", "frame", "data"
}

class PacketParser: 
    def parse(self, packet): 
        # test 
        parsed_packet = self.base_parsed_packet(packet)

        # process packet 
        # parsed_packet["packet"]["number"] = to_json_safe(packet.number)
        # parsed_packet["packet"]["sniff_time"] = to_json_safe(packet.sniff_time)
        # if "IP" in packet or "IPV6" in packet: 
        #     parsed_packet["packet"]["network"] = parse_network(packet)
        # else: 
        #     parsed_packet["packet"]["network"]["protocol"] = "UNKNOWN"

        # if "TCP" in packet or "UDP" in packet: 
        #     parsed_packet["packet"]["transport"] = parse_transport(packet)
        #     parsed_packet["packet"]["payload"] = parse_transport_payload(packet).decode("utf-8", errors="replace")
        # else: 
        #     parsed_packet["packet"]["transport"]["protocol"] = "UNKNOWN"
        #     parsed_packet["packet"]["payload"] = "UNKNOWN"
        parsed_packet["packet"] = parse_packet(packet)

        # process application if applicable
        parsed_packet["application"] = parse_application(packet)


        return parsed_packet
    
    def base_parsed_packet(self, packet): 
        return {
            "packet": {
            }, 
            "application": {
            }
        }

def parse_packet(packet): 
    def parse_network(packet): 
        if "IP" in packet:
            ip = packet.ip

            return {
                "version": 4,
                "protocol": "IP",
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "ttl": getattr(ip, "ttl", None),
                "transport_protocol": getattr(ip, "proto", None),
                "length": getattr(ip, "len", None),
                "id": getattr(ip, "id", None),
                "flags": getattr(ip, "flags", None),
                "fragment_offset": getattr(ip, "frag_offset", None),
            }
        elif "IPV6" in packet:
            ip = packet.ipv6

            return {
                "version": 6,
                "protocol": "IPV6",
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
    result = {
        "number": "-1",
        "sniff_time": "-1", 
        "network": {

        },
        "transport": {

        }, 
        "payload": {

        }
    }
    result["number"] = to_json_safe(packet.number)
    result["sniff_time"] = to_json_safe(packet.sniff_time)
    if "IP" in packet or "IPV6" in packet: 
        result["network"] = parse_network(packet)
    else: 
        result["network"]["protocol"] = "UNKNOWN"

    if "TCP" in packet or "UDP" in packet: 
        result["transport"] = parse_transport(packet)
        result["payload"] = parse_transport_payload(packet).decode("utf-8", errors="replace")
    else: 
        result["transport"]["protocol"] = "UNKNOWN"
        result["payload"] = "UNKNOWN"
    
    return result 





def parse_application(packet):
    def parse_http(http_layer):
        def get_field(name):
            return getattr(http_layer, name, None)

        # Common HTTP fields
        result = {
            "protocol": "HTTP",
            "content_type": get_field("content_type"),
            "content_length": get_field("content_length"),
            "host": get_field("host"),
            "user_agent": get_field("user_agent"),
            "connection": get_field("connection"),
            "body": get_field("file_data"),
        }

        # HTTP Request
        if get_field("request_method") is not None:
            result.update({
                "type": "request",
                "method": get_field("request_method"),
                "uri": get_field("request_uri"),
                "full_uri": get_field("request_full_uri"),
                "version": get_field("request_version"),
            })

        # HTTP Response
        elif get_field("response_code") is not None:
            result.update({
                "type": "response",
                "version": get_field("response_version"),
                "status_code": get_field("response_code"),
                "reason": get_field("response_phrase"),
                "server": get_field("server"),
            })

        else:
            result["type"] = "unknown"

        return result

    def parse_dns(dns_layer):
        # not yet implement
        result = {
            "protocol": "DNS"
        }
        return result 

    def parse_smtp(smtp_layer):
        # not yet implement 
        result = {
            "protocol": "DNS"
        }
        return result 

    def parse_data(data_layer):
        # not yet implement 
        # maybe need to implement custom parse http, dns, smtp để tránh những trường hợp pyshark không detect được 
        def get_field(name): 
            return getattr(data_layer, name, None)

        payload = get_field("data")
        payload = bytes.fromhex(payload.replace(":", "")) if payload else None 

        result = {
            "protocol": "UNKNOWN", 
            "raw": payload.decode("utf-8", errors="replace") if payload else None 
        }
        return result 

    def parse_dont_implement_protocol(app_layer):
        # not yet implement 
        result = {
            "protocol": "UNKNOWN(but PyShark can detect)"
        }
        return result 


    layers = packet.layers
    app_layer = None
    result = {
        "number": "-1", 
        "sniff_time": "-1",
        "network": {

        },
        "transport": {

        },
        "application": {

        }
    }

    '''
    thuật toán extract tầng application:
    - tìm layer đầu tiên trên transport
    - nếu không là data → lấy nó
    - nếu là data → kiểm tra trên tầng này còn layer gì không:
        - nếu có → lấy layer trên
        - nếu không → lấy layer data
'''

    for i, layer in enumerate(layers):
        if layer.layer_name.lower() in {"tcp", "udp"}:

            if i + 1 < len(layers):
                app_layer = layers[i + 1]

                if app_layer.layer_name.lower() == "data":
                    if i + 2 < len(layers):
                        app_layer = layers[i + 2]

            break

    if app_layer is None:
        return None
    
    result["number"] = to_json_safe(packet.number)
    result["sniff_time"] = to_json_safe(packet.sniff_time)

    # parse network 
    if "IP" in packet: 
        ip = packet.ip

        result["network"] = {
            "protocol": "IP",
            "source_ip": ip.src, 
            "dest_ip": ip.dst
        }
    elif "IPV6" in packet: 
        ip = packet.ipv6

        result["network"] = {
            "protocol": "IPV6",
            "source_ip": ip.src, 
            "dest_ip": ip.dst
        }
    else: 
        result["network"]["protocol"] = "UNKNOWN"
    
    # parse transport 
    if "TCP" in packet: 
        result["transport"] = {
            "protocol": "tcp", 
            "source_port": packet.tcp.srcport, 
            "dest_port": packet.tcp.dstport
        }
    
    elif "UDP" in packet: 
        result["transport"] = {
            "protocol": "udp", 
            "source_port": packet.udp.srcport, 
            "dest_port": packet.udp.dstport
        }
    
    else: 
        result["transport"]["protocol"] = "UNKNOWN"

    # parse application 
    if app_layer.layer_name.lower() == "http": 
        result["application"] = parse_http(app_layer)
        
    elif app_layer.layer_name.lower() == "dns":
        result["application"] = parse_dns(app_layer)

    elif app_layer.layer_name.lower() == "smtp":
        result["application"] = parse_smtp(app_layer)

    elif app_layer.layer_name.lower() == "data":
        result["application"] = parse_data(app_layer)

    else: # a protocol that pyshark can detect but not http, dns or smtp 
        result["application"] = parse_dont_implement_protocol(app_layer)

    return result

    
    






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