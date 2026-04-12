from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from snake_guard.engines import default_scan_engines
from snake_guard.models import (
    Dependency,
    DependencyType,
    EngineIssue,
    EngineStatus,
    Finding,
    FindingType,
    Inventory,
    PackageRisk,
    ScanResult,
)
from snake_guard.parsers import build_inventory
from snake_guard.parsers.common import pinned_version_from_specifier


def scan_project(root: Path, progress_callback: Callable[[str], None] | None = None) -> ScanResult:
    inventory = build_inventory(root)
    if progress_callback is not None:
        progress_callback(
            f"inventory: found {len(inventory.direct_dependencies())} direct and {len(inventory.resolved_dependencies())} resolved dependencies"
        )
    return scan_inventory(root, inventory, progress_callback=progress_callback)


def scan_dependencies(
    root: Path,
    dependencies: list[Dependency],
    manifests: list[str] | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> ScanResult:
    inventory = Inventory(root=root, dependencies=dependencies, manifests=manifests or [])
    if progress_callback is not None:
        progress_callback(
            f"inventory: prepared {len(inventory.direct_dependencies())} direct dependencies from explicit input"
        )
    return scan_inventory(root, inventory, progress_callback=progress_callback)


def scan_inventory(
    root: Path,
    inventory: Inventory,
    progress_callback: Callable[[str], None] | None = None,
) -> ScanResult:
    packages_by_name = _build_package_index(inventory.dependencies)
    issues: list[EngineIssue] = []
    engine_statuses: list[EngineStatus] = []

    engines = default_scan_engines()
    engine_runs = []
    with ThreadPoolExecutor(max_workers=len(engines)) as executor:
        future_map = {}
        for engine in engines:
            if progress_callback is not None:
                progress_callback(f"{engine.name}: started")
            future_map[executor.submit(engine.run, root, inventory.dependencies, progress_callback)] = engine.name
        for future in as_completed(future_map):
            engine_runs.append((future_map[future], future.result()))
            if progress_callback is not None:
                progress_callback(f"{future_map[future]}: completed")

    for engine_name, (findings_by_package, engine_issues) in engine_runs:
        engine_statuses.append(_engine_status(engine_name, findings_by_package, engine_issues))
        issues.extend(engine_issues)
        for package_name, findings in findings_by_package.items():
            package = packages_by_name.get(package_name)
            if package is None:
                package = PackageRisk(
                    package=package_name,
                    installed_version=_infer_installed_version(findings),
                    direct=False,
                )
                packages_by_name[package_name] = package
            package.findings.extend(findings)

    for package in packages_by_name.values():
        package.risk_level = _compute_risk_level(package.findings)
        package.recommended_action = _recommended_action(package.findings)

    return ScanResult(
        inventory=inventory,
        packages=sorted(
            packages_by_name.values(),
            key=lambda item: (_risk_rank(item.risk_level), item.package.lower()),
            reverse=True,
        ),
        issues=issues,
        engine_statuses=sorted(engine_statuses, key=lambda status: status.engine),
    )


def _engine_status(
    engine_name: str,
    findings_by_package: dict[str, list[Finding]],
    engine_issues: list[EngineIssue],
) -> EngineStatus:
    findings_count = sum(len(findings) for findings in findings_by_package.values())
    issues_count = len(engine_issues)
    status = "failed" if findings_count > 0 or issues_count > 0 else "passed"
    message_parts = []
    if findings_count:
        suffix = "finding" if findings_count == 1 else "findings"
        message_parts.append(f"{findings_count} {suffix}")
    if issues_count:
        suffix = "issue" if issues_count == 1 else "issues"
        message_parts.append(f"{issues_count} engine {suffix}")
    return EngineStatus(
        engine=engine_name,
        status=status,
        findings_count=findings_count,
        issues_count=issues_count,
        message=", ".join(message_parts) if message_parts else "no findings",
    )


def _build_package_index(dependencies: list[Dependency]) -> dict[str, PackageRisk]:
    package_map: dict[str, PackageRisk] = {}
    for dependency in dependencies:
        key = dependency.name.lower()
        package = package_map.get(key)
        candidate_version = dependency.resolved_version or _pinned_version(dependency.version_specifier)
        if package is None:
            package_map[key] = PackageRisk(
                package=dependency.name,
                installed_version=candidate_version,
                direct=dependency.dependency_type == DependencyType.DIRECT,
            )
            continue
        package.direct = package.direct or dependency.dependency_type == DependencyType.DIRECT
        if package.installed_version is None and candidate_version is not None:
            package.installed_version = candidate_version
    return package_map


def _compute_risk_level(findings: list[Finding]) -> str:
    if not findings:
        return "info"
    types = {finding.type for finding in findings}
    if FindingType.MALWARE_HEURISTIC in types:
        return "critical"
    if FindingType.KNOWN_VULN in types:
        return "high"
    if FindingType.MISSING_PROVENANCE in types or FindingType.MISSING_TRUSTED_PUBLISHING in types:
        return "medium"
    return "low"


def _recommended_action(findings: list[Finding]) -> str:
    has_fixable_vuln = any(finding.type == FindingType.KNOWN_VULN and finding.fixed_versions for finding in findings)
    if any(finding.type == FindingType.MALWARE_HEURISTIC for finding in findings):
        return "manual_review"
    if has_fixable_vuln:
        return "upgrade"
    if findings:
        return "manual_review"
    return "none"


def _pinned_version(specifier: str | None) -> str | None:
    return pinned_version_from_specifier(specifier)


def _infer_installed_version(findings: list[Finding]) -> str | None:
    return None


def _risk_rank(risk_level: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }.get(risk_level, 0)
