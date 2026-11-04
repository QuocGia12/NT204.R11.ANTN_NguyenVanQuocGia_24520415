from dataclasses import dataclass, field
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


@dataclass(frozen=True)
class AddressSpec:
    """Normalized rule address expression.

    ``values`` contains ``any``, IPv4 addresses, or CIDR strings.  Parsing
    and semantic validation are performed by the rule parser/validator; this
    class only stores the normalized expression.
    """

    values: tuple[str, ...] = ("any",)


@dataclass(frozen=True)
class PortSpec:
    """Normalized rule port expression."""

    is_any: bool = True
    values: tuple[int, ...] = ()
    ranges: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class ContentSpec:
    """One ordered Snort content option."""

    value: bytes
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None


@dataclass(frozen=True)
class FlagSpec:
    """Normalized TCP flag expression.

    ``mode`` is one of ``exact``, ``contains``, ``any_of`` or ``excludes``
    and represents the semantics of the optional Snort flag modifier.
    """

    mode: str = "exact"
    required: frozenset[str] = frozenset()
    forbidden: frozenset[str] = frozenset()


@dataclass(frozen=True)
class DSizeSpec:
    """Normalized dsize comparison."""

    operator: str
    value: int
    upper: int | None = None


@dataclass(frozen=True)
class Rule:
    """Validated internal representation of one supported Snort rule."""

    action: str
    protocol: str
    src_addresses: tuple[AddressSpec, ...]
    src_ports: PortSpec
    direction: str
    dst_addresses: tuple[AddressSpec, ...]
    dst_ports: PortSpec
    msg: str
    sid: int
    rev: int
    contents: tuple[ContentSpec, ...] = ()
    flags: FlagSpec | None = None
    dsize: DSizeSpec | None = None
    flow: frozenset[str] = frozenset()
    classtype: str | None = None
    priority: int | None = None
    raw_text: str = ""
    line_number: int | None = None

    def summary(self) -> dict[str, Any]:
        """Return rule identity and metadata for a detection event."""
        flag_summary = None
        if self.flags is not None:
            flag_summary = {
                "mode": self.flags.mode,
                "required": sorted(self.flags.required),
                "forbidden": sorted(self.flags.forbidden),
            }

        dsize_summary = None
        if self.dsize is not None:
            dsize_summary = {
                "operator": self.dsize.operator,
                "value": self.dsize.value,
                "upper": self.dsize.upper,
            }

        return {
            "action": self.action,
            "protocol": self.protocol,
            "msg": self.msg,
            "sid": self.sid,
            "rev": self.rev,
            "classtype": self.classtype,
            "priority": self.priority,
            "flow": sorted(self.flow),
            "flags": flag_summary,
            "dsize": dsize_summary,
            "content_count": len(self.contents),
            "raw": self.raw_text,
            "line_number": self.line_number,
        }


@dataclass(frozen=True)
class ValidationResult:
    """Result of parsing/validating one rule line."""

    valid: bool
    rule: Rule | None = None
    errors: tuple[str, ...] = ()
    raw_text: str = ""
    line_number: int | None = None

    @classmethod
    def ok(cls, rule: Rule) -> "ValidationResult":
        return cls(
            valid=True,
            rule=rule,
            raw_text=rule.raw_text,
            line_number=rule.line_number,
        )

    @classmethod
    def invalid(
        cls,
        errors: list[str] | tuple[str, ...],
        raw_text: str = "",
        line_number: int | None = None,
    ) -> "ValidationResult":
        return cls(
            valid=False,
            errors=tuple(errors),
            raw_text=raw_text,
            line_number=line_number,
        )


@dataclass(frozen=True)
class DetectionEvent:
    """One alert generated when a rule matches one packet."""

    timestamp: str | None
    packet_number: str | None
    flow_id: str | None
    rule: Rule
    packet: PacketContext
    match: Mapping[str, Any] = field(default_factory=dict)
    event_type: str = "alert"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe event representation."""
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "packet_number": self.packet_number,
            "flow_id": self.flow_id,
            "rule": self.rule.summary(),
            "packet": self.packet.summary(),
            "match": dict(self.match),
        }
