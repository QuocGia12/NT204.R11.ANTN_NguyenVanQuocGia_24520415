from dataclasses import dataclass
from typing import Any, Mapping


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)


@dataclass(frozen=True)
class PacketContext:
    """Normalized packet data consumed by the future rule matcher.

    The matcher receives this object instead of accessing PyShark fields or
    the JSON output schema directly.  ``payload`` remains bytes so content
    matching does not depend on UTF-8 decoding or replacement characters.
    """

    number: str | None
    timestamp: str | None
    protocol: str | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    payload: bytes
    tcp_flags: frozenset[str]
    payload_length: int
    flow_id: str | None
    flow_direction: str | None
    flow_flags: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.payload, bytes):
            raise TypeError("PacketContext.payload must be bytes")
        if self.payload_length != len(self.payload):
            raise ValueError("payload_length must equal len(payload)")

    @property
    def dsize(self) -> int:
        """Snort dsize value: transport payload length only."""
        return self.payload_length

    @classmethod
    def from_parsed_packet(
        cls,
        packet: Mapping[str, Any],
        payload: bytes,
        flow: Mapping[str, Any] | None = None,
    ) -> "PacketContext":
        """Build a context from the normalized packet dict and raw payload."""
        network = packet.get("network") or {}
        transport = packet.get("transport") or {}
        flow_data = flow or {}

        protocol = _optional_str(transport.get("protocol"))
        if protocol is not None:
            protocol = protocol.upper()

        flags = transport.get("flag_string", "")
        tcp_flags = frozenset(str(flags)) if protocol == "TCP" else frozenset()

        flow_flags_value = flow_data.get("flags", ())
        if isinstance(flow_flags_value, str):
            flow_flags_value = (flow_flags_value,)

        flow_id = flow_data.get("flow_id", packet.get("flow_id"))

        return cls(
            number=_optional_str(packet.get("number")),
            timestamp=_optional_str(packet.get("sniff_time")),
            protocol=protocol,
            src_ip=_optional_str(network.get("src_ip")),
            dst_ip=_optional_str(network.get("dst_ip")),
            src_port=_optional_int(transport.get("src_port")),
            dst_port=_optional_int(transport.get("dst_port")),
            payload=payload,
            tcp_flags=tcp_flags,
            payload_length=len(payload),
            flow_id=_optional_str(flow_id),
            flow_direction=_optional_str(flow_data.get("direction")),
            flow_flags=frozenset(str(flag) for flag in flow_flags_value),
        )

    def summary(self) -> dict[str, Any]:
        """Return a JSON-safe summary without embedding raw bytes."""
        return {
            "number": self.number,
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "payload_length": self.payload_length,
            "dsize": self.dsize,
            "tcp_flags": sorted(self.tcp_flags),
            "flow_id": self.flow_id,
            "flow_direction": self.flow_direction,
            "flow_flags": sorted(self.flow_flags),
        }
