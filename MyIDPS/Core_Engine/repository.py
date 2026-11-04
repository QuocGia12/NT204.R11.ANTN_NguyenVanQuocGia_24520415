"""Rule storage and header-based candidate selection."""

import ipaddress
from collections import defaultdict
from typing import Iterable

from .models import AddressSpec, PacketContext, PortSpec, Rule


IndexKey = tuple[str, int | None]


class RuleRepository:
    """Store validated rules and select rules worth sending to the matcher.

    The first index is keyed by ``(protocol, destination_port)``.  Rules with
    destination port ranges are kept in a protocol-specific range bucket, and
    bidirectional rules are kept in a protocol-specific bucket because either
    packet endpoint may be the rule destination.
    """

    def __init__(self, rules: Iterable[Rule] = ()) -> None:
        self._rules: list[Rule] = []
        self._positions: dict[int, int] = {}
        self._port_index: dict[IndexKey, list[Rule]] = defaultdict(list)
        self._range_rules: dict[str, list[Rule]] = defaultdict(list)
        self._bidirectional_rules: dict[str, list[Rule]] = defaultdict(list)
        self.add_all(rules)

    def add(self, rule: Rule) -> None:
        """Add one already validated rule and update the indexes."""
        if not isinstance(rule, Rule):
            raise TypeError("RuleRepository accepts Rule objects only")

        self._positions[id(rule)] = len(self._rules)
        self._rules.append(rule)
        protocol = _normalize_protocol(rule.protocol)

        if rule.direction == "<>":
            self._bidirectional_rules[protocol].append(rule)
            return

        if rule.dst_ports.is_any:
            self._port_index[(protocol, None)].append(rule)
            return

        for port in rule.dst_ports.values:
            self._port_index[(protocol, port)].append(rule)
        if rule.dst_ports.ranges:
            self._range_rules[protocol].append(rule)

    def add_all(self, rules: Iterable[Rule]) -> None:
        """Add all rules from an iterable."""
        for rule in rules:
            self.add(rule)

    @property
    def rules(self) -> tuple[Rule, ...]:
        """Return all stored rules in insertion order."""
        return tuple(self._rules)

    def __len__(self) -> int:
        return len(self._rules)

    def candidates(self, packet: PacketContext) -> tuple[Rule, ...]:
        """Return rules whose header can match ``packet``.

        Flow flags, TCP flags, dsize and content are intentionally not checked
        here.  Those conditions belong to the full matcher in later steps.
        """
        protocol = _normalize_protocol(packet.protocol)
        if protocol is None:
            return ()

        candidates: list[Rule] = []
        candidates.extend(
            self._port_index.get((protocol, packet.dst_port), ())
        )
        candidates.extend(self._port_index.get((protocol, None), ()))

        for rule in self._range_rules.get(protocol, ()):
            if _port_matches(rule.dst_ports, packet.dst_port):
                candidates.append(rule)

        candidates.extend(self._bidirectional_rules.get(protocol, ()))

        selected: list[Rule] = []
        seen: set[int] = set()
        for rule in candidates:
            identity = id(rule)
            if identity in seen:
                continue
            seen.add(identity)
            if _header_matches(rule, packet):
                selected.append(rule)
        selected.sort(key=lambda rule: self._positions[id(rule)])
        return tuple(selected)


def _normalize_protocol(protocol: str | None) -> str | None:
    if protocol is None:
        return None
    normalized = str(protocol).upper()
    return normalized or None


def _header_matches(rule: Rule, packet: PacketContext) -> bool:
    if _normalize_protocol(packet.protocol) != _normalize_protocol(rule.protocol):
        return False

    direct = _endpoint_pair_matches(
        rule.src_addresses,
        rule.src_ports,
        packet.src_ip,
        packet.src_port,
        rule.dst_addresses,
        rule.dst_ports,
        packet.dst_ip,
        packet.dst_port,
    )
    if rule.direction == "->":
        return direct
    if rule.direction == "<>":
        reverse = _endpoint_pair_matches(
            rule.src_addresses,
            rule.src_ports,
            packet.dst_ip,
            packet.dst_port,
            rule.dst_addresses,
            rule.dst_ports,
            packet.src_ip,
            packet.src_port,
        )
        return direct or reverse
    return False


def _endpoint_pair_matches(
    source_addresses: tuple[AddressSpec, ...],
    source_ports: PortSpec,
    packet_source_ip: str | None,
    packet_source_port: int | None,
    destination_addresses: tuple[AddressSpec, ...],
    destination_ports: PortSpec,
    packet_destination_ip: str | None,
    packet_destination_port: int | None,
) -> bool:
    return (
        _address_list_matches(source_addresses, packet_source_ip)
        and _port_matches(source_ports, packet_source_port)
        and _address_list_matches(destination_addresses, packet_destination_ip)
        and _port_matches(destination_ports, packet_destination_port)
    )


def _address_list_matches(
    addresses: tuple[AddressSpec, ...], packet_ip: str | None
) -> bool:
    return any(_address_matches(address, packet_ip) for address in addresses)


def _address_matches(address: AddressSpec, packet_ip: str | None) -> bool:
    for value in address.values:
        if value == "any":
            return True
        if packet_ip is None:
            continue
        try:
            parsed_ip = ipaddress.ip_address(packet_ip)
            if "/" in value:
                if parsed_ip in ipaddress.ip_network(value, strict=False):
                    return True
            elif parsed_ip == ipaddress.ip_address(value):
                return True
        except ValueError:
            continue
    return False


def _port_matches(port_spec: PortSpec, packet_port: int | None) -> bool:
    if port_spec.is_any:
        return True
    if packet_port is None:
        return False
    if packet_port in port_spec.values:
        return True
    return any(start <= packet_port <= end for start, end in port_spec.ranges)
