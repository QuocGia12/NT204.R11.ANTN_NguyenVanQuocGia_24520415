import pyshark
import json

class PacketParser: 
    def parse(self, packet): 
        # test 
        parsed_packet = {
            "packet": {

            }, 
            "application": {

            }
        }
        parsed_packet["packet"] = {
            "number": to_json_safe(packet.number), 
            "sniff_time": to_json_safe(packet.sniff_time), 
            "length": to_json_safe(packet.length), 
            "layers": to_json_safe(packet.layers)
        }
        return parsed_packet




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