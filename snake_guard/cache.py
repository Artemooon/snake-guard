from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from snake_guard import __version__
from snake_guard.engines.base import EngineResult
from snake_guard.models import EngineIssue, Finding, FindingType

CACHE_VERSION = 1
DEFAULT_TTL_SECONDS = 6 * 60 * 60  # 6 hours
CACHE_DIR_NAME = "snake-guard"
CACHE_FILE_NAME = "scan-cache.json"


class ScanCache:
    def __init__(
        self, path: Path | None = None, ttl_seconds: int = DEFAULT_TTL_SECONDS
    ) -> None:
        self.path = path or _default_cache_path()
        self.ttl_seconds = ttl_seconds
        self._lock = threading.RLock()
        self._data = self._load()

    def get(self, key: str) -> EngineResult | None:
        with self._lock:
            entry = self._data.get("entries", {}).get(key)
            if entry is None:
                return None
            created_at = float(entry.get("created_at", 0))
            if self.ttl_seconds > 0 and time.time() - created_at > self.ttl_seconds:
                self._data.get("entries", {}).pop(key, None)
                self._save_locked()
                return None
            return _engine_result_from_dict(entry.get("payload", {}))

    def set(self, key: str, result: EngineResult) -> None:
        with self._lock:
            self._data.setdefault("entries", {})[key] = {
                "created_at": time.time(),
                "payload": _engine_result_to_dict(result),
            }
            self._save_locked()

    def clear(self) -> None:
        with self._lock:
            self._data = {"version": CACHE_VERSION, "entries": {}}
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                return

    def _load(self) -> dict[str, Any]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {"version": CACHE_VERSION, "entries": {}}
        except OSError:
            return {"version": CACHE_VERSION, "entries": {}}

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return {"version": CACHE_VERSION, "entries": {}}

        if not isinstance(payload, dict) or payload.get("version") != CACHE_VERSION:
            return {"version": CACHE_VERSION, "entries": {}}

        entries = payload.get("entries", {})
        if not isinstance(entries, dict):
            entries = {}
        return {"version": CACHE_VERSION, "entries": entries}

    def _save_locked(self) -> None:
        payload = json.dumps(self._data, indent=2, sort_keys=True)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.path.parent,
                delete=False,
            ) as handle:
                handle.write(payload)
                temp_path = Path(handle.name)
            os.replace(temp_path, self.path)
        except OSError:
            return


def build_scan_cache_key(engine_name: str, inventory_payload: dict[str, Any]) -> str:
    payload = {
        "cache_version": CACHE_VERSION,
        "engine": engine_name,
        "python": list(sys.version_info[:3]),
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "snake_guard": __version__,
        "inventory": inventory_payload,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return digest.hexdigest()


def _default_cache_path() -> Path:
    cache_home = os.environ.get("XDG_CACHE_HOME")
    if cache_home:
        return Path(cache_home) / CACHE_DIR_NAME / CACHE_FILE_NAME
    return Path.home() / ".cache" / CACHE_DIR_NAME / CACHE_FILE_NAME


def _engine_result_to_dict(result: EngineResult) -> dict[str, Any]:
    findings_by_package, issues = result
    return {
        "findings_by_package": {
            package: [finding.to_dict() for finding in findings]
            for package, findings in findings_by_package.items()
        },
        "issues": [issue.to_dict() for issue in issues],
    }


def _engine_result_from_dict(payload: dict[str, Any]) -> EngineResult:
    findings_by_package: dict[str, list[Finding]] = {}
    raw_findings = payload.get("findings_by_package", {})
    if isinstance(raw_findings, dict):
        for package, findings in raw_findings.items():
            if not isinstance(findings, list):
                continue
            findings_by_package[package] = []
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                findings_by_package[package].append(
                    Finding(
                        type=FindingType(
                            finding.get("type", FindingType.KNOWN_VULN.value)
                        ),
                        source=str(finding.get("source", "")),
                        identifier=finding.get("identifier"),
                        detail=finding.get("detail"),
                        rule=finding.get("rule"),
                        severity=finding.get("severity"),
                        fixed_versions=list(finding.get("fixed_versions") or []),
                    )
                )
    issues: list[EngineIssue] = []
    raw_issues = payload.get("issues", [])
    if isinstance(raw_issues, list):
        for issue in raw_issues:
            if not isinstance(issue, dict):
                continue
            issues.append(
                EngineIssue(
                    engine=str(issue.get("engine", "")),
                    message=str(issue.get("message", "")),
                )
            )
    return findings_by_package, issues
