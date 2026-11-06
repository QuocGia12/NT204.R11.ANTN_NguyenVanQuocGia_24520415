"""Header and flow matching for normalized packets and rules."""

from collections.abc import Iterable

from .models import PacketContext, Rule
from .repository import header_matches


_FLOW_FLAGS = frozenset(
    {"to_server", "to_client", "established", "not_established"}
)
_TCP_ONLY_FLOW_FLAGS = frozenset({"established", "not_established"})


class RuleMatcher:
    """Match the parts of a rule implemented by step 9.

    Flags, dsize and content are deliberately left for later matcher steps.
    """

    def match(
        self,
        packet: PacketContext,
        rules: Iterable[Rule],
    ) -> tuple[Rule, ...]:
        """Return rules that match the packet header and flow flags."""
        return tuple(
            rule for rule in rules if self.matches(packet, rule)
        )

    def matches(self, packet: PacketContext, rule: Rule) -> bool:
        """Return whether one rule matches header and flow information."""
        return header_matches(rule, packet) and self._matches_flow(packet, rule)

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

