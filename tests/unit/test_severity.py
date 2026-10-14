"""Tests for the severity ordering."""

from __future__ import annotations

import pytest

from wyndoze_infoscanoverload.core.severity import Severity


def test_rank_is_strictly_ordered() -> None:
    ranks = [
        Severity.INFO.rank,
        Severity.LOW.rank,
        Severity.MEDIUM.rank,
        Severity.HIGH.rank,
        Severity.CRITICAL.rank,
    ]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("critical", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("  Medium ", Severity.MEDIUM),
        ("nonsense", Severity.INFO),
        ("", Severity.INFO),
    ],
)
def test_coerce(value: str, expected: Severity) -> None:
    assert Severity.coerce(value) == expected


def test_sorting_desc_by_rank() -> None:
    items = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]
    ordered = sorted(items, key=lambda s: s.rank, reverse=True)
    assert ordered[0] is Severity.CRITICAL
    assert ordered[-1] is Severity.LOW
