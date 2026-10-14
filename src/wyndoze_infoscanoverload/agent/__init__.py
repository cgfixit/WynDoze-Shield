"""Endpoint agent: collects safe telemetry and uploads or defers it.

Security posture (matching the skeleton's stated guarantees):
- Never reads file *contents*.
- Never collects credentials or secrets.
- Never performs active network scanning.
- Uploads over HTTPS with a bearer token; supports encrypted deferred upload
  for isolated machines.
"""

from __future__ import annotations
