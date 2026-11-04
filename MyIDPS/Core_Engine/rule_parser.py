import ipaddress
import re
from dataclasses import replace

from .models import (
    AddressSpec,
    ContentSpec,
    DSizeSpec,
    FlagSpec,
    PortSpec,
    Rule,
    ValidationResult,
)
from .validator import validate_rule


SUPPORTED_OPTIONS = frozenset(
    {
        "msg",
        "sid",
        "rev",
        "content",
        "nocase",
        "offset",
        "depth",
        "distance",
        "within",
        "flags",
        "dsize",
        "flow",
        "classtype",
        "priority",
    }
)

_TCP_FLAGS = frozenset("FSRPAUCE")
_FLOW_FLAGS = frozenset(
    {"to_server", "to_client", "established", "not_established"}
)
_INTEGER_OPTIONS = frozenset(
    {"sid", "rev", "offset", "depth", "distance", "within", "priority"}
)
_CONTENT_POSITION_OPTIONS = frozenset(
    {"nocase", "offset", "depth", "distance", "within"}
)


class RuleSyntaxError(ValueError):
    """Raised internally when one rule cannot be converted to a model."""


def parse_rule(rule_text: str, line_number: int | None = None) -> ValidationResult:
    """Parse one supported Snort rule into a ``ValidationResult``.

    Structural errors are returned as invalid results.  The loader can then
    report the rule and continue with the next line.
    """
    raw_text = rule_text.strip()
    try:
        header_text, options_text = _split_rule_sections(raw_text)
        (
            action,
            protocol,
            src_addresses,
            src_ports,
            direction,
            dst_addresses,
            dst_ports,
        ) = _parse_header(header_text)
        options = _parse_options(options_text)
        rule = _build_rule(
            raw_text=raw_text,
            line_number=line_number,
            action=action,
            protocol=protocol,
            src_addresses=src_addresses,
            src_ports=src_ports,
            direction=direction,
            dst_addresses=dst_addresses,
            dst_ports=dst_ports,
            options=options,
        )
        semantic_errors = validate_rule(rule)
        if semantic_errors:
            return ValidationResult.invalid(
                semantic_errors,
                raw_text=raw_text,
                line_number=line_number,
            )
        return ValidationResult.ok(rule)
    except RuleSyntaxError as exc:
        return ValidationResult.invalid(
            [str(exc)],
            raw_text=raw_text,
            line_number=line_number,
        )
    except (TypeError, ValueError) as exc:
        return ValidationResult.invalid(
            [f"syntax error: {exc}"],
            raw_text=raw_text,
            line_number=line_number,
        )


def _split_rule_sections(rule_text: str) -> tuple[str, str]:
    if not rule_text:
        raise RuleSyntaxError("empty rule")

    open_index = None
    quote = False
    escaped = False
    for index, char in enumerate(rule_text):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char == '"':
            quote = not quote
            continue
        if char == "(" and not quote:
            open_index = index
            break

    if quote:
        raise RuleSyntaxError("unterminated quote before options")
    if open_index is None:
        raise RuleSyntaxError("missing options opening '('")

    close_index = None
    quote = False
    escaped = False
    for index in range(open_index + 1, len(rule_text)):
        char = rule_text[index]
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char == '"':
            quote = not quote
            continue
        if char == ")" and not quote:
            close_index = index
            break

    if quote:
        raise RuleSyntaxError("unterminated quote in options")
    if close_index is None:
        raise RuleSyntaxError("missing options closing ')'")
    if rule_text[close_index + 1 :].strip():
        raise RuleSyntaxError("unexpected text after options")

    header = rule_text[:open_index].strip()
    options = rule_text[open_index + 1 : close_index].strip()
    if not header:
        raise RuleSyntaxError("missing rule header")
    return header, options


def _parse_header(
    header_text: str,
) -> tuple[
    str,
    str,
    tuple[AddressSpec, ...],
    PortSpec,
    str,
    tuple[AddressSpec, ...],
    PortSpec,
]:
    fields = header_text.split()
    if len(fields) != 7:
        raise RuleSyntaxError(
            f"header must contain 7 fields, got {len(fields)}"
        )

    action, protocol, src_address, src_port, direction, dst_address, dst_port = fields
    action = action.lower()
    protocol = protocol.lower()
    if action != "alert":
        raise RuleSyntaxError(f"unsupported action: {action}")
    if protocol not in {"tcp", "udp"}:
        raise RuleSyntaxError(f"unsupported protocol: {protocol}")
    if direction not in {"->", "<>"}:
        raise RuleSyntaxError(f"unsupported direction: {direction}")

    return (
        action,
        protocol.upper(),
        (_parse_address(src_address),),
        _parse_port(src_port),
        direction,
        (_parse_address(dst_address),),
        _parse_port(dst_port),
    )


def _parse_address(value: str) -> AddressSpec:
    if value == "any":
        return AddressSpec(("any",))

    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError as exc:
        raise RuleSyntaxError(f"invalid address: {value}") from exc
    return AddressSpec((value,))


def _parse_port(value: str) -> PortSpec:
    if value == "any":
        return PortSpec()

    if ":" in value:
        parts = value.split(":")
        if len(parts) != 2:
            raise RuleSyntaxError(f"invalid port range: {value}")
        start, end = _parse_port_number(parts[0], value), _parse_port_number(parts[1], value)
        if start > end:
            raise RuleSyntaxError(f"port range start exceeds end: {value}")
        return PortSpec(is_any=False, ranges=((start, end),))

    return PortSpec(is_any=False, values=(_parse_port_number(value, value),))


def _parse_port_number(value: str, original: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise RuleSyntaxError(f"invalid port: {original}") from exc
    if not 0 <= port <= 65535:
        raise RuleSyntaxError(f"port out of range: {original}")
    return port


def _parse_options(options_text: str) -> list[tuple[str, str | None]]:
    if not options_text:
        return []

    tokens = _split_option_tokens(options_text)
    options: list[tuple[str, str | None]] = []
    for token in tokens:
        key, value = _split_option_key_value(token)
        key = key.strip().lower()
        if not key:
            raise RuleSyntaxError("empty option keyword")
        if key not in SUPPORTED_OPTIONS:
            raise RuleSyntaxError(f"unsupported keyword: {key}")
        options.append((key, value.strip() if value is not None else None))
    return options


def _split_option_tokens(options_text: str) -> list[str]:
    tokens: list[str] = []
    start = 0
    quote = False
    escaped = False
    for index, char in enumerate(options_text):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char == '"':
            quote = not quote
            continue
        if char == ";" and not quote:
            token = options_text[start:index].strip()
            if token:
                tokens.append(token)
            start = index + 1

    if quote:
        raise RuleSyntaxError("unterminated quote in option")
    trailing = options_text[start:].strip()
    if trailing:
        tokens.append(trailing)
    return tokens


def _split_option_key_value(token: str) -> tuple[str, str | None]:
    quote = False
    escaped = False
    for index, char in enumerate(token):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char == '"':
            quote = not quote
            continue
        if char == ":" and not quote:
            return token[:index], token[index + 1 :]
    return token, None


def _build_rule(
    *,
    raw_text: str,
    line_number: int | None,
    action: str,
    protocol: str,
    src_addresses: tuple[AddressSpec, ...],
    src_ports: PortSpec,
    direction: str,
    dst_addresses: tuple[AddressSpec, ...],
    dst_ports: PortSpec,
    options: list[tuple[str, str | None]],
) -> Rule:
    values: dict[str, object] = {}
    contents: list[ContentSpec] = []
    seen_singletons: set[str] = set()

    for key, raw_value in options:
        if key in _CONTENT_POSITION_OPTIONS:
            if not contents:
                raise RuleSyntaxError(f"{key} requires a preceding content")
            _apply_content_option(contents, key, raw_value)
            continue

        if key == "content":
            if raw_value is None:
                raise RuleSyntaxError("content requires a quoted value")
            contents.append(ContentSpec(_decode_content(raw_value)))
            continue

        if key in {"msg", "sid", "rev", "flags", "dsize", "flow", "classtype", "priority"}:
            if key in seen_singletons:
                raise RuleSyntaxError(f"duplicate option: {key}")
            seen_singletons.add(key)

        if key == "msg":
            if raw_value is None:
                raise RuleSyntaxError("msg requires a quoted value")
            values[key] = _decode_text(raw_value)
        elif key in _INTEGER_OPTIONS:
            values[key] = _parse_nonnegative_int(key, raw_value)
        elif key == "flags":
            values[key] = _parse_flags(raw_value)
        elif key == "dsize":
            values[key] = _parse_dsize(raw_value)
        elif key == "flow":
            values[key] = _parse_flow(raw_value)
        elif key == "classtype":
            if not raw_value:
                raise RuleSyntaxError("classtype requires a value")
            values[key] = raw_value

    missing = [key for key in ("msg", "sid", "rev") if key not in values]
    if missing:
        raise RuleSyntaxError(f"missing required option(s): {', '.join(missing)}")

    return Rule(
        action=action,
        protocol=protocol,
        src_addresses=src_addresses,
        src_ports=src_ports,
        direction=direction,
        dst_addresses=dst_addresses,
        dst_ports=dst_ports,
        msg=values["msg"],
        sid=values["sid"],
        rev=values["rev"],
        contents=tuple(contents),
        flags=values.get("flags"),
        dsize=values.get("dsize"),
        flow=values.get("flow", frozenset()),
        classtype=values.get("classtype"),
        priority=values.get("priority"),
        raw_text=raw_text,
        line_number=line_number,
    )


def _apply_content_option(
    contents: list[ContentSpec],
    key: str,
    raw_value: str | None,
) -> None:
    if key == "nocase":
        if raw_value is not None:
            raise RuleSyntaxError("nocase does not accept a value")
        contents[-1] = replace(contents[-1], nocase=True)
        return

    value = _parse_nonnegative_int(key, raw_value)
    contents[-1] = replace(contents[-1], **{key: value})


def _parse_nonnegative_int(key: str, raw_value: str | None) -> int:
    if raw_value is None or not re.fullmatch(r"\d+", raw_value):
        raise RuleSyntaxError(f"{key} requires a non-negative integer")
    return int(raw_value)


def _parse_flags(raw_value: str | None) -> FlagSpec:
    if not raw_value:
        raise RuleSyntaxError("flags requires a value")

    mode = "exact"
    flag_text = raw_value
    if raw_value.endswith("+"):
        mode = "contains"
        flag_text = raw_value[:-1]
    elif raw_value.startswith("*"):
        mode = "any_of"
        flag_text = raw_value[1:]
    elif raw_value.startswith("!"):
        mode = "excludes"
        flag_text = raw_value[1:]

    if not flag_text or any(flag not in _TCP_FLAGS for flag in flag_text):
        raise RuleSyntaxError(f"invalid TCP flags: {raw_value}")

    if mode == "excludes":
        return FlagSpec(mode=mode, forbidden=frozenset(flag_text))
    return FlagSpec(mode=mode, required=frozenset(flag_text))


def _parse_dsize(raw_value: str | None) -> DSizeSpec:
    if raw_value is None:
        raise RuleSyntaxError("dsize requires a value")

    range_match = re.fullmatch(r"(\d+)<>(\d+)", raw_value)
    if range_match:
        lower, upper = int(range_match.group(1)), int(range_match.group(2))
        if lower > upper:
            raise RuleSyntaxError("dsize range lower bound exceeds upper bound")
        return DSizeSpec("range", lower, upper)

    comparison = re.fullmatch(r"(>=|<=|>|<)?(\d+)", raw_value)
    if not comparison:
        raise RuleSyntaxError(f"invalid dsize expression: {raw_value}")

    operator = {
        None: "eq",
        ">": "gt",
        "<": "lt",
        ">=": "ge",
        "<=": "le",
    }[comparison.group(1)]
    return DSizeSpec(operator, int(comparison.group(2)))


def _parse_flow(raw_value: str | None) -> frozenset[str]:
    if raw_value is None:
        raise RuleSyntaxError("flow requires at least one value")
    tokens = tuple(token.strip() for token in raw_value.split(","))
    if not tokens or any(token not in _FLOW_FLAGS for token in tokens):
        raise RuleSyntaxError(f"invalid flow expression: {raw_value}")
    return frozenset(tokens)


def _decode_text(raw_value: str) -> str:
    if len(raw_value) < 2 or raw_value[0] != '"' or raw_value[-1] != '"':
        raise RuleSyntaxError("value must be enclosed in double quotes")

    body = raw_value[1:-1]
    output: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            decoded, index = _decode_escape(body, index)
            output.append(decoded)
        else:
            output.append(char)
            index += 1
    return "".join(output)


def _decode_content(raw_value: str) -> bytes:
    if len(raw_value) < 2 or raw_value[0] != '"' or raw_value[-1] != '"':
        raise RuleSyntaxError("content must be enclosed in double quotes")

    body = raw_value[1:-1]
    output = bytearray()
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            decoded, index = _decode_escape(body, index)
            output.extend(decoded.encode("utf-8"))
        elif char == "|":
            end = body.find("|", index + 1)
            if end == -1:
                raise RuleSyntaxError("unterminated hex content block")
            hex_text = body[index + 1 : end]
            compact = "".join(hex_text.split())
            if not compact or len(compact) % 2:
                raise RuleSyntaxError("hex content must contain complete bytes")
            try:
                output.extend(bytes.fromhex(compact))
            except ValueError as exc:
                raise RuleSyntaxError("invalid hex content") from exc
            index = end + 1
        else:
            output.extend(char.encode("utf-8"))
            index += 1
    return bytes(output)


def _decode_escape(value: str, index: int) -> tuple[str, int]:
    if index + 1 >= len(value):
        raise RuleSyntaxError("unterminated escape sequence")
    escaped = value[index + 1]
    simple = {
        "n": "\n",
        "r": "\r",
        "t": "\t",
        '"': '"',
        "\\": "\\",
    }
    if escaped in simple:
        return simple[escaped], index + 2
    if escaped == "x" and index + 3 < len(value):
        hex_value = value[index + 2 : index + 4]
        if re.fullmatch(r"[0-9A-Fa-f]{2}", hex_value):
            return chr(int(hex_value, 16)), index + 4
    raise RuleSyntaxError(f"unsupported escape sequence: \\{escaped}")
