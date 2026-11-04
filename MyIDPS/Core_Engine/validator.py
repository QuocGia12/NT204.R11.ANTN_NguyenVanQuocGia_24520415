"""Semantic validation for the normalized Core Engine rule model."""

import ipaddress

from .models import AddressSpec, ContentSpec, DSizeSpec, FlagSpec, PortSpec, Rule


_VALID_ACTIONS = frozenset({"alert"})
_VALID_PROTOCOLS = frozenset({"TCP", "UDP"})
_VALID_DIRECTIONS = frozenset({"->", "<>"})
_VALID_FLAG_MODES = frozenset({"exact", "contains", "any_of", "excludes"})
_VALID_DSIZE_OPERATORS = frozenset({"eq", "gt", "lt", "ge", "le", "range"})
_VALID_TCP_FLAGS = frozenset("FSRPAUCE")
_VALID_FLOW_FLAGS = frozenset(
    {"to_server", "to_client", "established", "not_established"}
)


def validate_rule(rule: Rule) -> tuple[str, ...]:
    """Return semantic validation errors for one normalized rule.

    The parser has already converted text into model objects by this point.
    This function therefore checks relationships between fields instead of
    splitting or decoding rule text.
    """
    errors: list[str] = []
    errors.extend(_validate_header(rule))
    errors.extend(_validate_identification(rule))
    errors.extend(_validate_content(rule.contents))
    errors.extend(_validate_flags(rule))
    errors.extend(_validate_dsize(rule.dsize))
    errors.extend(_validate_flow(rule))
    return tuple(errors)


class RuleValidator:
    """Small object-oriented wrapper for callers that prefer a validator object."""

    def validate(self, rule: Rule) -> tuple[str, ...]:
        return validate_rule(rule)


def _validate_header(rule: Rule) -> list[str]:
    errors: list[str] = []
    if rule.action not in _VALID_ACTIONS:
        errors.append(f"unsupported action: {rule.action}")
    if rule.protocol not in _VALID_PROTOCOLS:
        errors.append(f"unsupported protocol: {rule.protocol}")
    if rule.direction not in _VALID_DIRECTIONS:
        errors.append(f"unsupported direction: {rule.direction}")

    for label, addresses in (
        ("source", rule.src_addresses),
        ("destination", rule.dst_addresses),
    ):
        if not addresses:
            errors.append(f"{label} address is missing")
        for address in addresses:
            errors.extend(_validate_address(label, address))

    errors.extend(_validate_port("source", rule.src_ports))
    errors.extend(_validate_port("destination", rule.dst_ports))
    return errors


def _validate_address(label: str, address: AddressSpec) -> list[str]:
    errors: list[str] = []
    if not address.values:
        return [f"{label} address is empty"]

    for value in address.values:
        if value == "any":
            continue
        try:
            if "/" in value:
                ipaddress.ip_network(value, strict=False)
            else:
                ipaddress.ip_address(value)
        except ValueError:
            errors.append(f"invalid {label} address: {value}")
    return errors


def _validate_port(label: str, port: PortSpec) -> list[str]:
    errors: list[str] = []
    if port.is_any:
        if port.values or port.ranges:
            errors.append(f"{label} port marked any but has values")
        return errors

    for value in port.values:
        if not 0 <= value <= 65535:
            errors.append(f"{label} port out of range: {value}")
    for start, end in port.ranges:
        if not 0 <= start <= 65535 or not 0 <= end <= 65535:
            errors.append(f"{label} port range out of range: {start}:{end}")
        elif start > end:
            errors.append(f"{label} port range start exceeds end: {start}:{end}")

    if not port.values and not port.ranges:
        errors.append(f"{label} port is empty")
    return errors


def _validate_identification(rule: Rule) -> list[str]:
    errors: list[str] = []
    if not isinstance(rule.msg, str) or not rule.msg.strip():
        errors.append("msg is required")
    if (
        not isinstance(rule.sid, int)
        or isinstance(rule.sid, bool)
        or rule.sid <= 0
    ):
        errors.append("sid must be a positive integer")
    if (
        not isinstance(rule.rev, int)
        or isinstance(rule.rev, bool)
        or rule.rev <= 0
    ):
        errors.append("rev must be a positive integer")
    if rule.priority is not None and (
        not isinstance(rule.priority, int)
        or isinstance(rule.priority, bool)
        or rule.priority <= 0
    ):
        errors.append("priority must be a positive integer")
    if rule.classtype is not None and not rule.classtype.strip():
        errors.append("classtype must not be empty")
    return errors


def _validate_content(contents: tuple[ContentSpec, ...]) -> list[str]:
    errors: list[str] = []
    for index, content in enumerate(contents, start=1):
        prefix = f"content {index}"
        if not isinstance(content.value, bytes):
            errors.append(f"{prefix} must contain bytes")
        if isinstance(content.value, bytes) and not content.value:
            errors.append(f"{prefix} must not be empty")

        for name in ("offset", "depth", "distance", "within"):
            value = getattr(content, name)
            if value is not None and (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                errors.append(f"{prefix} {name} must be non-negative")

        if (
            content.offset is not None
            and content.depth is not None
            and content.depth < content.offset
        ):
            errors.append(f"{prefix} depth must not be smaller than offset")
    return errors


def _validate_flags(rule: Rule) -> list[str]:
    if rule.flags is None:
        return []

    errors: list[str] = []
    if rule.protocol != "TCP":
        errors.append("flags is only valid for TCP rules")

    flags = rule.flags
    if flags.mode not in _VALID_FLAG_MODES:
        errors.append(f"invalid flag mode: {flags.mode}")
    if not flags.required and not flags.forbidden:
        errors.append("flags must contain at least one TCP flag")
    if any(flag not in _VALID_TCP_FLAGS for flag in flags.required):
        errors.append("flags contains an unsupported TCP flag")
    if any(flag not in _VALID_TCP_FLAGS for flag in flags.forbidden):
        errors.append("flags contains an unsupported TCP flag")
    if flags.mode == "excludes" and not flags.forbidden:
        errors.append("excludes flags must define forbidden flags")
    if flags.mode != "excludes" and flags.forbidden:
        errors.append("only excludes flags may define forbidden flags")
    return errors


def _validate_dsize(dsize: DSizeSpec | None) -> list[str]:
    if dsize is None:
        return []

    errors: list[str] = []
    if dsize.operator not in _VALID_DSIZE_OPERATORS:
        errors.append(f"invalid dsize operator: {dsize.operator}")
    value_is_valid = (
        isinstance(dsize.value, int)
        and not isinstance(dsize.value, bool)
        and dsize.value >= 0
    )
    if not value_is_valid:
        errors.append("dsize value must be non-negative")
    if dsize.operator == "range":
        if dsize.upper is None:
            errors.append("dsize range requires an upper bound")
        else:
            upper_is_valid = (
                isinstance(dsize.upper, int)
                and not isinstance(dsize.upper, bool)
                and dsize.upper >= 0
            )
            if not upper_is_valid:
                errors.append("dsize upper bound must be non-negative")
            elif value_is_valid and dsize.upper < dsize.value:
                errors.append("dsize range lower bound exceeds upper bound")
    elif dsize.upper is not None:
        errors.append("only range dsize may define an upper bound")
    return errors


def _validate_flow(rule: Rule) -> list[str]:
    errors: list[str] = []
    unknown = set(rule.flow) - _VALID_FLOW_FLAGS
    if unknown:
        errors.append(f"invalid flow flag(s): {', '.join(sorted(unknown))}")

    if rule.protocol == "UDP":
        forbidden = rule.flow & {"established", "not_established"}
        if forbidden:
            errors.append(
                "UDP rules cannot use flow:established or "
                "flow:not_established"
            )
    return errors
