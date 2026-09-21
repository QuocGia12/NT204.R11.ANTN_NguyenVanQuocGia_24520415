from scapy.packet import Packet

class PacketParser: 
    def parse(self, packet: Packet): 
        res = {
            "packet": str(packet)
        }
        return res 