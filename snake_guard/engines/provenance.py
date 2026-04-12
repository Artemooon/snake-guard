from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

from snake_guard.engines.base import MAX_EXTERNAL_WORKERS, EngineResult, ProgressCallback, ScanEngine
from snake_guard.models import Dependency, DependencyType, EngineIssue, Finding, FindingType
from snake_guard.parsers.common import pinned_version_from_specifier

PYPI_BASE_URL = "https://pypi.org"


class ProvenanceEngine(ScanEngine):
    name = "provenance"

    def run(
        self,
        root: Path,
        dependencies: list[Dependency],
        progress_callback: ProgressCallback = None,
    ) -> EngineResult:
        findings_by_package: dict[str, list[Finding]] = defaultdict(list)
        issues: list[EngineIssue] = []
        candidates = []
        for dependency in dependencies:
            version = dependency.resolved_version or self._pinned_version(dependency.version_specifier)
            if dependency.dependency_type != DependencyType.DIRECT or version is None:
                continue
            candidates.append((dependency, version))

        if not candidates:
            return findings_by_package, issues

        with ThreadPoolExecutor(max_workers=min(MAX_EXTERNAL_WORKERS, len(candidates))) as executor:
            future_map = {
                executor.submit(
                    self._check_dependency,
                    dependency,
                    version,
                    progress_callback,
                ): (dependency, version)
                for dependency, version in candidates
            }
            for future in as_completed(future_map):
                dependency, _ = future_map[future]
                package_findings, package_issue = future.result()
                if package_issue is not None:
                    issues.append(package_issue)
                    continue
                findings_by_package[dependency.name.lower()].extend(package_findings)
        return findings_by_package, issues

    def _check_dependency(
        self,
        dependency: Dependency,
        version: str,
        progress_callback: ProgressCallback = None,
    ) -> tuple[list[Finding], EngineIssue | None]:
        if progress_callback is not None:
            progress_callback(f"provenance: checking {dependency.name}=={version}")
        try:
            try:
                release = self._fetch_json(
                    f"{PYPI_BASE_URL}/pypi/{urllib.parse.quote(dependency.name)}/{urllib.parse.quote(version)}/json"
                )
            except urllib.error.HTTPError as exc:
                return [], EngineIssue(engine="pypi", message=f"{dependency.name}: PyPI returned HTTP {exc.code}")
            except urllib.error.URLError as exc:
                return [], EngineIssue(engine="pypi", message=f"{dependency.name}: unable to reach PyPI: {exc.reason}")

            urls = release.get("urls", [])
            if not urls:
                return [
                    Finding(
                        type=FindingType.MISSING_PROVENANCE,
                        source="pypi",
                        detail="no release files found for the resolved version",
                        severity="medium",
                    )
                ], None

            release_findings = self._check_release_provenance(dependency.name, version, urls)
            if progress_callback is not None:
                progress_callback(f"provenance: finished {dependency.name}=={version}")
            return release_findings, None
        except urllib.error.HTTPError as exc:
            return [], EngineIssue(engine="pypi", message=f"{dependency.name}: PyPI returned HTTP {exc.code}")

    def _check_release_provenance(self, name: str, version: str, urls: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        trusted_publishing = False
        attestations_found = False

        for file_info in urls:
            filename = file_info.get("filename")
            if not filename:
                continue
            endpoint = (
                f"{PYPI_BASE_URL}/integrity/{urllib.parse.quote(name)}/"
                f"{urllib.parse.quote(version)}/{urllib.parse.quote(filename)}/provenance"
            )
            try:
                provenance = self._fetch_json(endpoint)
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    continue
                raise
            bundles = provenance.get("attestation_bundles", [])
            if not bundles:
                continue
            attestations_found = True
            for bundle in bundles:
                publisher = bundle.get("publisher", {})
                kind = str(publisher.get("kind", "")).lower()
                if any(token in kind for token in ("github", "gitlab", "google")):
                    trusted_publishing = True

        if not attestations_found:
            findings.append(
                Finding(
                    type=FindingType.MISSING_PROVENANCE,
                    source="pypi",
                    detail="no attestations were found for this release",
                    severity="medium",
                )
            )
        elif not trusted_publishing:
            findings.append(
                Finding(
                    type=FindingType.MISSING_TRUSTED_PUBLISHING,
                    source="pypi",
                    detail="attestations exist, but trusted publishing identity was not detected",
                    severity="medium",
                )
            )
        return findings

    def _fetch_json(self, url: str) -> dict:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "snake-guard/0.1.0",
            },
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))

    def _pinned_version(self, specifier: str | None) -> str | None:
        return pinned_version_from_specifier(specifier)
