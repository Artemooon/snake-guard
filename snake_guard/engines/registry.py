from __future__ import annotations

from snake_guard.engines.base import ScanEngine
from snake_guard.engines.guarddog import GuarddogEngine
from snake_guard.engines.pip_audit import PipAuditEngine
from snake_guard.engines.provenance import ProvenanceEngine


def default_scan_engines() -> list[ScanEngine]:
    return [PipAuditEngine(), GuarddogEngine(), ProvenanceEngine()]

