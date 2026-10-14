"""Bundled rule packs shipped inside the wheel."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from wyndoze_infoscanoverload.core.rules import RulePack, load_rule_pack

DEFAULT_PACK_NAME = "windows_default.yaml"


def default_rule_pack() -> RulePack:
    """Load the rule pack bundled with the package."""
    with resources.as_file(
        resources.files(__package__).joinpath(DEFAULT_PACK_NAME)
    ) as path:
        return load_rule_pack(Path(path))


__all__ = ["DEFAULT_PACK_NAME", "default_rule_pack"]
