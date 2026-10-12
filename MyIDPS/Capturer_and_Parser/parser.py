import pyshark
import json
import argparse 
from html import unescape
from urllib.parse import unquote, unquote_plus

NON_APPLICATION_LAYERS = {
    "eth", "sll", "sll2", "ip", "ipv6",
    "tcp", "udp", "icmp", "icmpv6",
    "arp", "vlan", "frame", "data"
}

DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    255: "ANY",
}

DNS_CLASSES = {1: "IN", 3: "CH", 4: "HS"}

class PacketParser: 
    def parse(self, packet, flow_id): 
        # test 
        parsed_packet = self.base_parsed_packet(packet)

        # process packet 
        parsed_packet["packet"] = parse_packet(packet)
        parsed_packet["packet"]["flow_id"] = flow_id 

        # process application if applicable
        parsed_packet["application"] = parse_application(packet)
        if parsed_packet["application"] is not None: 
            parsed_packet["application"]["flow_id"] = flow_id 


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

            flags = {
                "F": packet.tcp.flags_fin,
                "S": packet.tcp.flags_syn,
                "R": packet.tcp.flags_reset,
                "P": packet.tcp.flags_push,
                "A": packet.tcp.flags_ack,
                "U": packet.tcp.flags_urg,
                "E": packet.tcp.flags_ecn,
                "C": packet.tcp.flags_cwr,
            }

            flag_string = "".join(
                name for name, value in flags.items()
                if str(value) == "1"
            )

            return {
                "protocol": "TCP",
                "src_port": int(tcp.srcport),
                "dst_port": int(tcp.dstport),
                "seq": int(tcp.seq),
                "ack": int(tcp.ack),
                "flags": tcp.flags,
                "flag_string": flag_string,
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

        def get_headers():
            headers = {}

            # Request -> request_line
            # Response -> response_line
            if get_field("request_method") is not None:
                field = http_layer.get_field("request_line")

            elif get_field("response_code") is not None:
                field = http_layer.get_field("response_line")

            else:
                return headers

            if field is None:
                return headers

            for item in field.all_fields:
                line = item.show

                if not line or ":" not in line:
                    continue

                name, value = line.split(":", 1)

                name = name.strip()
                value = value.strip()

                # Same header can appear multiple times
                if name in headers:
                    if isinstance(headers[name], list):
                        headers[name].append(value)
                    else:
                        headers[name] = [
                            headers[name],
                            value,
                        ]
                else:
                    headers[name] = value

            return headers

        result = {
            "protocol": "HTTP",
            "headers": get_headers(),
            "body": get_field("file_data"),
        }

        content_type = next(
            (value for name, value in result["headers"].items()
             if name.lower() == "content-type"),
            None,
        )
        if isinstance(content_type, list):
            content_type = content_type[0]
        media_type = (
            content_type.split(";", 1)[0].strip().lower()
            if isinstance(content_type, str) else None
        )
        body = result["body"]
        if media_type == "application/x-www-form-urlencoded" and isinstance(body, str) and body:
            result["body_url_decode"] = unquote_plus(body)

        # HTTP Request
        if get_field("request_method") is not None:
            full_uri = get_field("request_full_uri")
            result.update({
                "type": "request",
                "method": get_field("request_method"),
                "uri": get_field("request_uri"),
                "full_uri": full_uri,
                "decoded_full_uri": unquote(full_uri) if full_uri is not None else None,
                "version": get_field("request_version"),
            })

        # HTTP Response
        elif get_field("response_code") is not None:
            result.update({
                "type": "response",
                "version": get_field("response_version"),
                "status_code": get_field("response_code"),
                "reason": get_field("response_phrase"),
            })

            if (
                media_type == "text/html"
                and isinstance(body, str)
                and body
            ):
                result["decoded_text"] = unescape(body)

        else:
            result["type"] = "unknown"

        return result

    def parse_dns(dns_layer):
        """Parse một DNS layer của PyShark thành các RR theo đúng section.

        Yêu cầu PyShark ở chế độ XML mặc định: mỗi LayerField có show, pos, size.
        Khi số trường chung không khớp số RR trong header, hàm ghi parse_errors
        và không tự ghép các giá trị có thể thuộc nhầm record.
        """

        def all_fields(name):
            container = dns_layer.get_field(name)
            return list(container.all_fields) if container is not None else []

        def first_value(name):
            values = all_fields(name)
            return values[0].show if values else None

        def as_int(value):
            if value is None:
                return None
            try:
                return int(str(value))
            except ValueError:
                try:
                    return int(str(value), 0)
                except ValueError:
                    return None

        def type_name(code):
            return DNS_TYPES.get(code, f"TYPE{code}")

        def class_name(code):
            return DNS_CLASSES.get(code, f"CLASS{code}")

        def one(fields, name):
            values = fields.get(name, [])
            return values[0] if values else None

        def parse_rdata(rr_type, fields):
            """Đặt tên dễ đọc cho RDATA thông dụng; giữ raw_fields cho loại khác."""
            if rr_type in ("A", "AAAA"):
                return {"address": one(fields, rr_type.lower())}
            if rr_type == "CNAME":
                return {"target": one(fields, "cname")}
            if rr_type == "NS":
                return {"nameserver": one(fields, "ns")}
            if rr_type == "PTR":
                return {"target": one(fields, "ptr_domain_name")}
            if rr_type == "MX":
                return {
                    "preference": as_int(one(fields, "mx_preference")),
                    "exchange": one(fields, "mx_mail_exchange"),
                }
            if rr_type == "TXT":
                return {"strings": fields.get("txt", [])}
            if rr_type == "SRV":
                return {
                    "priority": as_int(one(fields, "srv_priority")),
                    "weight": as_int(one(fields, "srv_weight")),
                    "port": as_int(one(fields, "srv_port")),
                    "target": one(fields, "srv_target"),
                }
            if rr_type == "SOA":
                return {
                    "mname": one(fields, "soa_mname"),
                    "rname": one(fields, "soa_rname"),
                    "serial": as_int(one(fields, "soa_serial_number")),
                    "refresh": as_int(one(fields, "soa_refresh_interval")),
                    "retry": as_int(one(fields, "soa_retry_interval")),
                    "expire": as_int(one(fields, "soa_expire_limit")),
                    "minimum": as_int(one(fields, "soa_minimum_ttl")),
                }
            return fields.copy()

        # parse headers 
        question_count = as_int(first_value("count_queries")) or 0
        answer_count = as_int(first_value("count_answers")) or 0
        authority_count = as_int(first_value("count_auth_rr")) or 0
        additional_count = as_int(first_value("count_add_rr")) or 0
        response_flag = first_value("flags_response")

        result = {
            "protocol": "DNS",
            "transaction_id": first_value("id"),
            "flags": first_value("flags"),
            "opcode": as_int(first_value("flags_opcode")),
            "response_code": as_int(first_value("flags_rcode")),
            "question_count": question_count,
            "answer_count": answer_count,
            "authority_count": authority_count,
            "additional_count": additional_count,
            "type": {"0": "query", "1": "response"}.get(response_flag, "unknown"),
            "query": None,
            "questions": [],
            "answers": [],
            "authorities": [],
            "additionals": [],
            "parse_errors": [],
        }

        # parse dns question
        question_fields = {  
            "name": all_fields("qry_name"),
            "type": all_fields("qry_type"),
            "class": all_fields("qry_class"),
        }
        
        # kiểm tra có bao nhiêu question, các value thu được có đủ số lượng với question count không 
        question_lengths = {key: len(value) for key, value in question_fields.items()}
        if any(length != question_count for length in question_lengths.values()):
            result["parse_errors"].append(
                f"question count {question_count} differs from fields {question_lengths}"
            )
        else:
            for index in range(question_count): # duyệt từng question và parse 
                code = as_int(question_fields["type"][index].show)
                class_code = as_int(question_fields["class"][index].show)
                result["questions"].append({
                    "name": question_fields["name"][index].show,
                    "type": type_name(code),
                    "type_code": code,
                    "class": class_name(class_code),
                    "class_code": class_code,
                })
            if result["questions"]:
                result["query"] = result["questions"][0] # query: question đầu tiên 


        total_records = answer_count + authority_count + additional_count
        common = {
            "name": all_fields("resp_name"),
            "type": all_fields("resp_type"),
            "class": all_fields("resp_class"),
            "ttl": all_fields("resp_ttl"),
            "length": all_fields("resp_len"),
        }
        common_lengths = {key: len(value) for key, value in common.items()}
        if any(length != total_records for length in common_lengths.values()):
            result["parse_errors"].append(
                f"RR count {total_records} differs from fields {common_lengths}"
            )
            return result

        # Giữ vị trí của tất cả trường để gắn chúng với RDATA của đúng RR.
        rdata_fields = []
        common_names = {"resp_name", "resp_type", "resp_class", "resp_ttl", "resp_len"}
        for field_name in dns_layer.field_names:
            if not field_name or field_name in common_names:
                continue
            for field in all_fields(field_name):
                position = as_int(getattr(field, "pos", None))
                if position is not None:
                    rdata_fields.append((position, field_name, field.show))

        records = []
        for index in range(total_records):
            type_code = as_int(common["type"][index].show)
            class_code = as_int(common["class"][index].show)
            ttl = as_int(common["ttl"][index].show)
            length = as_int(common["length"][index].show)
            length_field = common["length"][index]
            length_pos = as_int(getattr(length_field, "pos", None))
            length_size = as_int(getattr(length_field, "size", None))

            if None in (length, length_pos, length_size):
                result["parse_errors"].append(f"RR {index}: missing RDATA boundary")
                return result

            rdata_start = length_pos + length_size
            rdata_end = rdata_start + length
            fields = {}
            for position, name, value in rdata_fields:
                if rdata_start <= position < rdata_end:
                    fields.setdefault(name, []).append(value)

            rr_type = type_name(type_code)
            record = {
                "name": common["name"][index].show,
                "type": rr_type,
                "type_code": type_code,
                "class": class_name(class_code),
                "class_code": class_code,
                "ttl": ttl,
                "rdata_length": length,
                "rdata": parse_rdata(rr_type, fields),
                "raw_fields": fields,
            }

            # OPT là pseudo-RR: CLASS chứa UDP payload size, TTL chứa EDNS flags.
            if type_code == 41:
                record["udp_payload_size"] = class_code
                record["edns_ttl_raw"] = ttl
                record["class"] = None
                record["ttl"] = None

            records.append(record)

        result["answers"] = records[:answer_count]
        result["authorities"] = records[answer_count:answer_count + authority_count]
        result["additionals"] = records[answer_count + authority_count:]
        return result


    def parse_smtp(smtp_layer):
        def get_field(name):
            return smtp_layer.get_field_value(name)

        def get_all_fields(name):
            field = smtp_layer.get_field(name)

            if field is None:
                return []

            return [
                item.show
                for item in field.all_fields
                if item.show is not None
            ]

        def merge_fields(name, separator=" "):
            values = get_all_fields(name)

            if not values:
                return None

            return separator.join(values)

        result = {
            "protocol": "SMTP",
            "type": "unknown",
        }


        # End of message
        if "eom" in smtp_layer.field_names:
            result["type"] = "end_of_message"
            return result

        # AUTH
        auth_username = get_field("auth_username")
        auth_password = get_field("auth_password")

        if auth_username is not None:
            result["type"] = "auth"
            result["auth_type"] = "username"
            result["username"] = auth_username
            return result

        if auth_password is not None:
            result["type"] = "auth"
            result["auth_type"] = "password"
            result["auth_password_present"] = True
            return result

        # SMTP request
        command = merge_fields("req_command")
        arg = merge_fields("req_parameter")

        if command is not None:
            result["type"] = "request"

            command = command.strip()


            if command.upper() == "MAIL" and arg:
                stripped_arg = arg.strip()

                if stripped_arg.upper().startswith("FROM:"):
                    command = "MAIL FROM"
                    arg = stripped_arg[5:].strip()

                elif stripped_arg.upper().startswith("FROM "):
                    command = "MAIL FROM"
                    arg = stripped_arg[5:].strip()


            elif command.upper() == "RCPT" and arg:
                stripped_arg = arg.strip()

                if stripped_arg.upper().startswith("TO:"):
                    command = "RCPT TO"
                    arg = stripped_arg[3:].strip()

                elif stripped_arg.upper().startswith("TO "):
                    command = "RCPT TO"
                    arg = stripped_arg[3:].strip()

            result["command"] = command

            if arg:
                result["arg"] = arg

            return result

        # SMTP response
        response_code = merge_fields("response_code")
        response_message = merge_fields("rsp_parameter")

        if response_code is not None:
            result["type"] = "response"
            result["response_code"] = response_code

            if response_message:
                result["message"] = response_message

            return result

        # SMTP DATA
        field = smtp_layer.get_field("")

        if field is not None:
            result["type"] = "data"

            result["message"] = "".join(
                item.show
                for item in field.all_fields
                if item.show is not None
            )

        # Reassembly information
        data_fragment_count = get_field("data_fragment_count")
        data_reassembled_length = get_field("data_reassembled_length")
        data_fragments = get_all_fields("data_fragment")

        if data_fragment_count is not None:
            result["data_fragment_count"] = data_fragment_count

        if data_reassembled_length is not None:
            result["data_reassembled_length"] = data_reassembled_length

        if data_fragments:
            result["data_fragments"] = data_fragments

        return result

    def parse_data(data_layer):
        def get_field(name): 
            return getattr(data_layer, name, None)

        payload = get_field("data")
        payload = bytes.fromhex(payload.replace(":", "")) if payload else None 

        result = {
            "protocol": "UNKNOWN", 
            "raw": payload.decode("utf-8", errors="replace") if payload else None 
        }
        return result 

    def parse_dont_implement_protocol(app_layer): # protocol that pyshark can detect but not http, dns, smtp
        result = {
            "protocol": app_layer.layer_name.upper(),
            "fields": {}
        }

        for name in app_layer.field_names:
            field = app_layer.get_field(name)

            if field is None:
                continue

            values = [
                item.show
                for item in field.all_fields
            ]

            if not values:
                continue

            # Handle unnamed fields
            field_name = name if name else "data"

            result["fields"][field_name] = (
                values[0] if len(values) == 1 else values
            )

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
