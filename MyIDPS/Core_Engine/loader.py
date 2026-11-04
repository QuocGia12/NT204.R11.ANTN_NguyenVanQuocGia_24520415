from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .models import Rule, ValidationResult


RuleParser = Callable[[str, int], ValidationResult]
WarningSink = Callable[[str], None]


@dataclass(frozen=True)
class RuleLoadReport:
    """Result of loading one rule file."""

    source: str
    rules: tuple[Rule, ...]
    invalid: tuple[ValidationResult, ...]
    skipped_lines: int = 0

    @property
    def accepted_count(self) -> int:
        return len(self.rules)

    @property
    def invalid_count(self) -> int:
        return len(self.invalid)


class RuleParserUnavailableError(RuntimeError):
    """Raised when load() is called before the rule parser is available."""


class RuleLoader:
    """Load supported Snort rule lines without stopping at invalid rules.

    The parser is injected so the loader remains independently testable.  In
    the final engine, callers can omit it after ``rule_parser.py`` exists and
    exposes ``parse_rule(text, line_number)``.
    """

    def __init__(
        self,
        parse_rule: RuleParser | None = None,
        warning_sink: WarningSink | None = None,
    ) -> None:
        self._parse_rule = parse_rule
        self._warning_sink = warning_sink or print

    def load(self, path: str | Path) -> RuleLoadReport:
        """Read a UTF-8 .rules file and return accepted/invalid rules."""
        rule_path = Path(path)
        text = rule_path.read_text(encoding="utf-8")
        return self.load_text(text, source=str(rule_path))

    def load_text(self, text: str, source: str = "<text>") -> RuleLoadReport:
        """Load rules from text; useful for unit tests and generated rules."""
        parser = self._resolve_parser()
        rules: list[Rule] = []
        invalid: list[ValidationResult] = []
        skipped_lines = 0

        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            rule_text = raw_line.strip()
            if not rule_text or rule_text.startswith("#"):
                skipped_lines += 1
                continue

            result = self._parse_one(parser, rule_text, line_number)
            if result.valid and result.rule is not None:
                rules.append(result.rule)
                continue

            if result.valid and result.rule is None:
                result = ValidationResult.invalid(
                    ["parser returned a valid result without a rule"],
                    raw_text=rule_text,
                    line_number=line_number,
                )
            elif result.line_number is None or not result.raw_text:
                result = ValidationResult.invalid(
                    result.errors or ("invalid rule",),
                    raw_text=result.raw_text or rule_text,
                    line_number=result.line_number or line_number,
                )

            invalid.append(result)
            self._emit_invalid(result)

        return RuleLoadReport(
            source=source,
            rules=tuple(rules),
            invalid=tuple(invalid),
            skipped_lines=skipped_lines,
        )

    def _resolve_parser(self) -> RuleParser:
        if self._parse_rule is not None:
            return self._parse_rule

        try:
            from .rule_parser import parse_rule
        except ImportError as exc:
            raise RuleParserUnavailableError(
                "No rule parser is available. Pass parse_rule=... or "
                "implement Core_Engine.rule_parser.parse_rule()."
            ) from exc
        return parse_rule

    @staticmethod
    def _parse_one(
        parser: RuleParser,
        rule_text: str,
        line_number: int,
    ) -> ValidationResult:
        try:
            result = parser(rule_text, line_number)
        except Exception as exc:  # One bad rule must not stop the file.
            return ValidationResult.invalid(
                [f"parser error: {exc}"],
                raw_text=rule_text,
                line_number=line_number,
            )

        if not isinstance(result, ValidationResult):
            return ValidationResult.invalid(
                ["parser did not return ValidationResult"],
                raw_text=rule_text,
                line_number=line_number,
            )
        return result

    def _emit_invalid(self, result: ValidationResult) -> None:
        reason = "; ".join(result.errors) or "invalid rule"
        line_number = result.line_number if result.line_number is not None else "?"
        self._warning_sink(
            f"[INVALID] line {line_number}: {reason}\n  {result.raw_text}"
        )
