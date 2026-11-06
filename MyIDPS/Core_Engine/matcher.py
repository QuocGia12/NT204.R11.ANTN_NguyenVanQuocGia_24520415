"""Header, flow and TCP flag matching for normalized packets and rules."""

from collections.abc import Iterable

from .models import PacketContext, Rule
from .repository import header_matches


_FLOW_FLAGS = frozenset(
    {"to_server", "to_client", "established", "not_established"}
)
_TCP_ONLY_FLOW_FLAGS = frozenset({"established", "not_established"})


class RuleMatcher:
    """Match normalized packet data against the implemented rule conditions.

    Header, flow and TCP flag matching are implemented here.  Dsize and
    content are deliberately left for later matcher steps.
    """

    def match(
        self,
        packet: PacketContext,
        rules: Iterable[Rule],
    ) -> tuple[Rule, ...]:
        """Return rules that match the packet header, flow and TCP flags."""
        return tuple(
            rule for rule in rules if self.matches(packet, rule)
        )

    def matches(self, packet: PacketContext, rule: Rule) -> bool:
        """Return whether one rule matches header, flow and flags."""
        return (
            header_matches(rule, packet)
            and self._matches_flow(packet, rule)
            and self._matches_flags(packet, rule)
        )

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
