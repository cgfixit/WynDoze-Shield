"""WynDoze-InfoScanOverload endpoint scanner and dashboard.

Agents collect local inventory. A loopback server scores it with MITRE
ATT&CK rules and shows a triage inbox.
"""

from __future__ import annotations

from wyndoze_infoscanoverload._version import __version__

__all__ = ["__version__"]
