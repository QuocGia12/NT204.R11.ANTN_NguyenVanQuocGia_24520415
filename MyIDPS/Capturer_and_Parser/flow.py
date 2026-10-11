from datetime import datetime


def empty_direction() -> dict:
    return {
        "start_time": None,
        "last_seen": None,
        "packet_count": 0,
        "byte_count": 0,
        "syn_count": 0,
        "ack_count": 0,
        "fin_count": 0,
        "rst_count": 0,
    }


def iso_time(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def duration_seconds(start: datetime | None, end: datetime | None) -> float:
    if start is None or end is None:
        return 0.0
    return max(0.0, (end - start).total_seconds())


class FlowTracker:
    def __init__(self, udp_idle_seconds: float = 60.0):
        self.udp_idle_seconds = udp_idle_seconds
        self.flow_table: dict[str, dict] = {}
        self._tcp_by_stream: dict[str, str] = {} # mapping tcp.stream -> flow_id 
        self._udp_by_endpoints: dict[tuple, str] = {} # mapping cặp endpoints -> flow_id 
        self._next_id = 1

    def _create_flow(
        self,
        protocol: str,
        source: tuple[str, int], # (source ip, source port)
        destination: tuple[str, int], # (dst ip, dst port)
        seen_at: datetime,
        tcp_stream: str | None = None,
    ) -> str:
        flow_id = f"flow-{self._next_id:06d}"
        self._next_id += 1

        self.flow_table[flow_id] = {
            "flow_id": flow_id,
            "protocol": protocol,
            "tcp_stream": tcp_stream,
            "endpoint_a": {"ip": source[0], "port": source[1]},
            "endpoint_b": {"ip": destination[0], "port": destination[1]},
            "start_time": seen_at,
            "last_seen": seen_at,
            "directions": {
                "a_to_b": empty_direction(),
                "b_to_a": empty_direction(),
            },
        }
        if protocol == "TCP":
            flow = self.flow_table[flow_id]
            flow["stage"] = "handshake"
            flow["_tcp_stage"] = {
                "initiator": None,
                "syn_ack_seen": False,
                "fin_seen": {"a_to_b": False, "b_to_a": False},
                "fin_acked": {"a_to_b": False, "b_to_a": False},
            }

        return flow_id
    def _update_tcp_stage(self, flow: dict, tcp, direction: str) -> None:
        if flow["stage"] == "closed":
            return

        state = flow["_tcp_stage"]
        other = "b_to_a" if direction == "a_to_b" else "a_to_b"
        syn = str(getattr(tcp, "flags_syn", "0")) == "1"
        ack = str(getattr(tcp, "flags_ack", "0")) == "1"
        fin = str(getattr(tcp, "flags_fin", "0")) == "1"
        rst = str(getattr(tcp, "flags_reset", "0")) == "1"

        if rst:
            flow["stage"] = "closed"
            return

        # ACK từ chiều hiện tại có thể xác nhận FIN của chiều đối diện.
        if ack and state["fin_seen"][other]:
            state["fin_acked"][other] = True

        if fin:
            state["fin_seen"][direction] = True
            flow["stage"] = "closing"

        if flow["stage"] == "closing":
            sides = ("a_to_b", "b_to_a")
            if (
                all(state["fin_seen"][side] for side in sides)
                and all(state["fin_acked"][side] for side in sides)
            ):
                flow["stage"] = "closed"
            return

        if flow["stage"] == "established":
            return

        # Handshake: SYN -> SYN+ACK -> ACK từ chiều khởi tạo.
        if syn and not ack:
            if state["initiator"] is None:
                state["initiator"] = direction
            return

        if syn and ack:
            if state["initiator"] is None:
                state["initiator"] = other  # capture bắt đầu từ SYN+ACK
            if state["initiator"] == other:
                state["syn_ack_seen"] = True
            return

        if ack and state["syn_ack_seen"] and direction == state["initiator"]:
            flow["stage"] = "established"
            return

        # Packet đầu không có SYN hoặc có data: capture có thể thiếu handshake.
        packet_count = sum(
            stats["packet_count"] for stats in flow["directions"].values()
        )
        try:
            has_data = int(getattr(tcp, "len", "0")) > 0
        except (TypeError, ValueError):
            has_data = False
        if packet_count == 1 or has_data:
            flow["stage"] = "established"


    def observe(self, packet) -> str | None:
        """Nhận một packet, cập nhật đúng một flow và trả về flow_id."""
        if "IP" in packet:
            ip_layer = packet.ip
        elif "IPV6" in packet:
            ip_layer = packet.ipv6
        else:
            return None

        if "TCP" in packet:
            protocol = "TCP"
            transport = packet.tcp
        elif "UDP" in packet:
            protocol = "UDP"
            transport = packet.udp
        else:
            return None

        try:
            source = (ip_layer.src, int(transport.srcport)) # (source ip, source port)
            destination = (ip_layer.dst, int(transport.dstport)) # (dst ip, dst port)
            seen_at = packet.sniff_time # sniff time 
        except (AttributeError, TypeError, ValueError):
            return None

        if protocol == "TCP": # tcp 
            stream = getattr(transport, "stream", None) # tcp.stream 
            if stream is None:
                return None

            stream = str(stream)
            flow_id = self._tcp_by_stream.get(stream) 
            if flow_id is None: # nếu chưa có flow id đó thì tạo flow mới 
                flow_id = self._create_flow(
                    protocol, source, destination, seen_at, tcp_stream=stream
                )
                self._tcp_by_stream[stream] = flow_id

        else: # udp 
            # sorted() khiến A:port -> B:port và B:port -> A:port có cùng khóa.
            key = tuple(sorted((source, destination)))
            flow_id = self._udp_by_endpoints.get(key)

            if flow_id is not None:
                last_seen = self.flow_table[flow_id]["last_seen"]
                idle = (seen_at - last_seen).total_seconds()
                if idle > self.udp_idle_seconds: # nếu như có cặp endpoints đó trong table rồi nhưng thời gian của packet gần nhất đã hơn 60s thì xem như là flow id mới 
                    flow_id = None

            if flow_id is None:
                flow_id = self._create_flow(protocol, source, destination, seen_at)
                self._udp_by_endpoints[key] = flow_id

        flow = self.flow_table[flow_id]
        endpoint_a = (flow["endpoint_a"]["ip"], flow["endpoint_a"]["port"])
        direction = "a_to_b" if source == endpoint_a else "b_to_a"
        stats = flow["directions"][direction]

        stats["start_time"] = min(stats["start_time"], seen_at) if stats["start_time"] else seen_at
        stats["last_seen"] = max(stats["last_seen"], seen_at) if stats["last_seen"] else seen_at
        flow["start_time"] = min(flow["start_time"], seen_at)
        flow["last_seen"] = max(flow["last_seen"], seen_at)
        stats["packet_count"] += 1

        # frame.len có trong packet PyShark; packet.length là phương án dự phòng.
        frame_length = getattr(getattr(packet, "frame_info", None), "len", None)
        if frame_length is None:
            frame_length = getattr(packet, "length", 0)
        try:
            stats["byte_count"] += int(frame_length)
        except (TypeError, ValueError):
            pass

        if protocol == "TCP":
            for field, counter in (
                ("flags_syn", "syn_count"),
                ("flags_ack", "ack_count"),
                ("flags_fin", "fin_count"),
                ("flags_reset", "rst_count"),
            ):
                if str(getattr(transport, field, "0")) == "1":
                    stats[counter] += 1
            
            self._update_tcp_stage(flow, transport, direction)

        return flow_id

    def snapshot(self) -> list[dict]:
        """Trả về bản ghi JSON-serializable, không sửa trạng thái tracker."""
        result = []
        for flow in self.flow_table.values():
            record = {
                "flow_id": flow["flow_id"],
                "protocol": flow["protocol"],
                "tcp_stream": flow["tcp_stream"],
                "endpoint_a": flow["endpoint_a"],
                "endpoint_b": flow["endpoint_b"],
                "start_time": iso_time(flow["start_time"]),
                "last_seen": iso_time(flow["last_seen"]),
                "duration": duration_seconds(flow["start_time"], flow["last_seen"]),
                "directions": {},
            }
            if flow["protocol"] == "TCP":
                record["stage"] = flow["stage"]

            for name, stats in flow["directions"].items():
                record["directions"][name] = {
                    "start_time": iso_time(stats["start_time"]),
                    "last_seen": iso_time(stats["last_seen"]),
                    "duration": duration_seconds(stats["start_time"], stats["last_seen"]),
                    "packet_count": stats["packet_count"],
                    "byte_count": stats["byte_count"],
                    "syn_count": stats["syn_count"],
                    "ack_count": stats["ack_count"],
                    "fin_count": stats["fin_count"],
                    "rst_count": stats["rst_count"],
                }

            result.append(record)

        return result
