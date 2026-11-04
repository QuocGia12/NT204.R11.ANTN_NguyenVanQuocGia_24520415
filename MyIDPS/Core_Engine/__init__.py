"""Core Engine models and rule-processing components."""

from .models import (
    AddressSpec,
    ContentSpec,
    DetectionEvent,
    DSizeSpec,
    FlagSpec,
    PacketContext,
    PortSpec,
    Rule,
    ValidationResult,
)
from .loader import RuleLoadReport, RuleLoader, RuleParserUnavailableError
from .repository import RuleRepository
from .rule_parser import SUPPORTED_OPTIONS, RuleSyntaxError, parse_rule
from .validator import RuleValidator, validate_rule

__all__ = [
    "AddressSpec",
    "ContentSpec",
    "DetectionEvent",
    "DSizeSpec",
    "FlagSpec",
    "PacketContext",
    "PortSpec",
    "Rule",
    "RuleLoadReport",
    "RuleLoader",
    "RuleParserUnavailableError",
    "RuleRepository",
    "RuleSyntaxError",
    "RuleValidator",
    "SUPPORTED_OPTIONS",
    "ValidationResult",
    "parse_rule",
    "validate_rule",
]
