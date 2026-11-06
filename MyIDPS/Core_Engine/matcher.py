"""Header, flow and TCP flag matching for normalized packets and rules."""

from collections.abc import Iterable
from typing import Any

from .models import DetectionEvent, PacketContext, Rule
from .repository import header_matches


_FLOW_FLAGS = frozenset(
    {"to_server", "to_client", "established", "not_established"}
)
_TCP_ONLY_FLOW_FLAGS = frozenset({"established", "not_established"})


class RuleMatcher:
    """Match normalized packet data against the implemented rule conditions.

    Header, flow, TCP flag, dsize and content matching are implemented here.
    """

    def match(
        self,
        packet: PacketContext,
        rules: Iterable[Rule],
    ) -> tuple[Rule, ...]:
        """Return rules matching header, flow, flags, dsize and content."""
        return tuple(
            rule for rule in rules if self.matches(packet, rule)
        )

    def match_events(
        self,
        packet: PacketContext,
        rules: Iterable[Rule],
    ) -> tuple[DetectionEvent, ...]:
        """Create one detection event for every rule that matches ``packet``."""
        events: list[DetectionEvent] = []
        for rule in rules:
            event = self.match_event(packet, rule)
            if event is not None:
                events.append(event)
        return tuple(events)

    def match_event(
        self,
        packet: PacketContext,
        rule: Rule,
    ) -> DetectionEvent | None:
        """Return one event for a matching rule, or ``None`` otherwise."""
        match_details = self._match_details(packet, rule)
        if match_details is None:
            return None

        return DetectionEvent(
            timestamp=packet.timestamp,
            packet_number=packet.number,
            flow_id=packet.flow_id,
            rule=rule,
            packet=packet,
            match=match_details,
        )

    def matches(self, packet: PacketContext, rule: Rule) -> bool:
        """Return whether one rule matches all implemented conditions."""
        return self._match_details(packet, rule) is not None

    def _match_details(
        self,
        packet: PacketContext,
        rule: Rule,
    ) -> dict[str, Any] | None:
        """Run all matchers and build JSON-safe match metadata."""
        if not header_matches(rule, packet):
            return None
        if not self._matches_flow(packet, rule):
            return None
        if not self._matches_flags(packet, rule):
            return None
        if not self._matches_dsize(packet, rule):
            return None

        content_matches = self._content_match_details(packet, rule)
        if content_matches is None:
            return None

        details: dict[str, Any] = {
            "protocol": packet.protocol,
            "direction": packet.flow_direction,
            "matched_contents": list(content_matches),
            "payload_offset": (
                content_matches[0]["offset"] if content_matches else None
            ),
            "dsize": packet.dsize,
            "tcp_flags": sorted(packet.tcp_flags),
            "flags": "".join(sorted(packet.tcp_flags)),
        }
        if content_matches:
            display_values = [
                self._display_content(content.value)
                for content in rule.contents
            ]
            details["matched_content"] = (
                display_values[0]
                if len(display_values) == 1
                else display_values
            )
        return details

    @staticmethod
    def _display_content(value: bytes) -> str:
        """Return a JSON-safe content label without exposing packet payload."""
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return f"hex:{value.hex()}"

    @staticmethod
    def _matches_flow(packet: PacketContext, rule: Rule) -> bool:
        """Require every flow token in the rule to be present on the packet."""
        required = set(rule.flow)
        if not required:
            return True
        if not required.issubset(_FLOW_FLAGS):
            return False

        protocol = (packet.protocol or "").upper()
        if protocol == "UDP" and required & _TCP_ONLY_FLOW_FLAGS:
            return False
        if protocol != "TCP" and required & _TCP_ONLY_FLOW_FLAGS:
            return False

        return required.issubset(packet.flow_flags)

    @staticmethod
    def _matches_flags(packet: PacketContext, rule: Rule) -> bool:
        """Match a rule's TCP flags against the normalized packet flags.

        ``FlagSpec`` has already been normalized by the rule parser:

        - ``exact`` requires the packet flags to be exactly ``required``;
        - ``contains`` requires ``required`` but permits other flags;
        - ``any_of`` requires at least one required flag;
        - ``excludes`` rejects packets containing a forbidden flag.

        A flags condition is meaningful only for TCP.  Returning ``False``
        for a non-TCP packet also protects callers that construct a ``Rule``
        directly without going through the parser/validator.
        """
        flag_spec = rule.flags
        if flag_spec is None:
            return True

        if (packet.protocol or "").upper() != "TCP":
            return False

        packet_flags = frozenset(packet.tcp_flags)
        required = frozenset(flag_spec.required)
        forbidden = frozenset(flag_spec.forbidden)

        if flag_spec.mode == "exact":
            return packet_flags == required
        if flag_spec.mode == "contains":
            return required.issubset(packet_flags)
        if flag_spec.mode == "any_of":
            return bool(packet_flags & required)
        if flag_spec.mode == "excludes":
            return not (packet_flags & forbidden)
        return False

    @staticmethod
    def _matches_dsize(packet: PacketContext, rule: Rule) -> bool:
        """Match a rule's dsize condition against raw payload length.

        ``PacketContext.dsize`` is the length of the raw TCP/UDP transport
        payload.  It deliberately does not include Ethernet, IP, TCP or UDP
        headers.
        """
        dsize_spec = rule.dsize
        if dsize_spec is None:
            return True

        dsize = packet.dsize
        operator = dsize_spec.operator
        value = dsize_spec.value

        if operator == "eq":
            return dsize == value
        if operator == "gt":
            return dsize > value
        if operator == "lt":
            return dsize < value
        if operator == "ge":
            return dsize >= value
        if operator == "le":
            return dsize <= value
        if operator == "range":
            return (
                dsize_spec.upper is not None
                and value <= dsize <= dsize_spec.upper
            )
        return False

    @staticmethod
    def _matches_content(packet: PacketContext, rule: Rule) -> bool:
        """Match all ordered content conditions against the raw payload."""
        return RuleMatcher._content_match_details(packet, rule) is not None

    @staticmethod
    def _content_match_details(
        packet: PacketContext,
        rule: Rule,
    ) -> tuple[dict[str, int], ...] | None:
        """Return offsets for all content matches, or ``None`` on failure.

        Content checks are evaluated in declaration order.  A content without
        a location modifier starts searching from the beginning of the buffer,
        matching Snort's default behavior.  ``distance`` and ``within`` make a
        content relative to the cursor immediately after the previous match.
        """
        if not rule.contents:
            return ()

        payload = packet.payload
        cursor = 0
        payload_length = len(payload)
        matches: list[dict[str, int]] = []

        for content in rule.contents:
            value = content.value
            if not isinstance(value, bytes) or not value:
                return None
            if any(
                modifier is not None and (
                    not isinstance(modifier, int)
                    or isinstance(modifier, bool)
                    or modifier < 0
                )
                for modifier in (
                    content.offset,
                    content.depth,
                    content.distance,
                    content.within,
                )
            ):
                return None
            if (
                content.offset is not None
                and content.depth is not None
                and content.depth < content.offset
            ):
                return None

            if content.distance is not None:
                start = cursor + content.distance
            elif content.offset is not None:
                start = content.offset
            elif content.within is not None:
                # Snort treats within without distance as distance 0.
                start = cursor
            else:
                # No modifier means search from the beginning of the buffer.
                start = 0

            end = payload_length
            if content.depth is not None:
                depth_origin = content.offset if content.offset is not None else 0
                end = min(end, depth_origin + content.depth)
            if content.within is not None:
                end = min(end, cursor + content.within)

            if start > end:
                return None

            haystack = payload.lower() if content.nocase else payload
            needle = value.lower() if content.nocase else value
            match_start = haystack.find(needle, start, end)
            if match_start < 0:
                return None

            matches.append(
                {
                    "content_index": len(matches),
                    "offset": match_start,
                    "length": len(value),
                }
            )
            cursor = match_start + len(value)

        return tuple(matches)
