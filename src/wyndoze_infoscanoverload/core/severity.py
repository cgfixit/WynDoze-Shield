"""Severity ladder shared by the agent, rules engine, and server."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Ordered severity levels.

    ``StrEnum`` (PEP 663, 3.11+) keeps values JSON-friendly while still giving
    us an ``Enum`` for type safety. Ordering is defined explicitly via
    :data:`_ORDER` rather than relying on declaration order so comparisons are
    unambiguous.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Return a monotonically increasing integer for ordering."""
        return _ORDER[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    @classmethod
    def coerce(cls, value: str | Severity) -> Severity:
        """Parse a possibly-messy string into a :class:`Severity`.

        Unknown values fall back to :attr:`INFO` rather than raising, so a
        malformed rule file cannot crash ingestion.
        """
        if isinstance(value, Severity):
            return value
        try:
            return cls(value.strip().lower())
        except ValueError:
            return cls.INFO


_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
