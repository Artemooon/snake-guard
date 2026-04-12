from __future__ import annotations

import difflib
import re
from pathlib import Path

from packaging.version import InvalidVersion, Version

from snake_guard.models import (
    Dependency,
    DependencyType,
    FindingType,
    FixAction,
    FixPlan,
    FixRecommendation,
    PackageRisk,
    ScanResult,
)


def build_fix_plan(root: Path, result: ScanResult, apply: bool = False) -> tuple[FixPlan, str | None]:
    requirements_path = root / "requirements.txt"
    direct_by_name = {
        dependency.name.lower(): dependency
        for dependency in result.inventory.direct_dependencies()
        if dependency.source_file == "requirements.txt"
    }

    actions: list[FixAction] = []
    recommendations = _pinning_recommendations(result.inventory.dependencies)
    warnings: list[str] = []
    replacement_map: dict[str, str] = {}

    for package in result.packages:
        plan_action = _action_for_package(package)
        if plan_action is None:
            continue
        if plan_action.action == "upgrade":
            direct_dependency = direct_by_name.get(package.package.lower())
            if direct_dependency is None:
                warnings.append(
                    f"{package.package}: safe upgrade found, but automatic edits are only implemented for requirements.txt direct dependencies"
                )
                actions.append(plan_action)
                continue
            replacement_map[package.package.lower()] = f"{package.package}=={plan_action.target_version}"
            plan_action.manifest = "requirements.txt"
        actions.append(plan_action)

    diff: str | None = None
    if replacement_map and requirements_path.exists():
        original = requirements_path.read_text(encoding="utf-8").splitlines(keepends=True)
        updated = [_replace_requirement_line(line, replacement_map) for line in original]
        if original != updated:
            diff = "".join(
                difflib.unified_diff(
                    original,
                    updated,
                    fromfile="requirements.txt",
                    tofile="requirements.txt",
                )
            )
            if apply:
                requirements_path.write_text("".join(updated), encoding="utf-8")
                for action in actions:
                    if action.manifest == "requirements.txt" and action.action == "upgrade":
                        action.applied = True

    if any(action.action == "manual_review" for action in actions):
        warnings.extend(post_compromise_hygiene())

    return FixPlan(actions=actions, recommendations=recommendations, warnings=warnings), diff


def _pinning_recommendations(dependencies: list[Dependency]) -> list[FixRecommendation]:
    recommendations: list[FixRecommendation] = []
    seen: set[tuple[str, str | None]] = set()
    resolved_versions = {
        dependency.name.lower(): dependency.resolved_version
        for dependency in dependencies
        if dependency.dependency_type == DependencyType.RESOLVED and dependency.resolved_version
    }
    for dependency in dependencies:
        if dependency.dependency_type != DependencyType.DIRECT:
            continue
        if dependency.pinned:
            continue
        key = (dependency.name.lower(), dependency.source_file)
        if key in seen:
            continue
        seen.add(key)
        recommendations.append(
            FixRecommendation(
                package=dependency.name,
                recommendation="Pin this direct dependency to an exact version.",
                manifest=dependency.source_file,
                current_specifier=dependency.version_specifier,
                recommended_specifier=_recommended_pin_specifier(resolved_versions.get(dependency.name.lower())),
                direct=True,
            )
        )
    return recommendations


def _recommended_pin_specifier(version: str | None) -> str | None:
    if version is None:
        return None
    return f"=={version}"


def post_compromise_hygiene() -> list[str]:
    return [
        "Remove the current virtual environment and rebuild it from a clean dependency set.",
        "Clear the local pip download and wheel caches before reinstalling.",
        "Rotate credentials that may have been exposed to package install hooks or runtime code.",
        "Rescan the repository and CI environment for secrets or unexpected file changes.",
        "Review shell init files, CI tokens, and developer machine persistence points for tampering.",
    ]


def _action_for_package(package: PackageRisk) -> FixAction | None:
    suspicious = any(finding.type == FindingType.MALWARE_HEURISTIC for finding in package.findings)
    if suspicious:
        return FixAction(
            package=package.package,
            action="manual_review",
            direct=package.direct,
            detail="Package triggered GuardDog heuristics. Do not auto-replace silently.",
        )

    fix_versions = []
    for finding in package.findings:
        if finding.type == FindingType.KNOWN_VULN:
            fix_versions.extend(finding.fixed_versions)
    if fix_versions:
        target_version = _highest_version(fix_versions)
        return FixAction(
            package=package.package,
            action="upgrade",
            target_version=target_version,
            direct=package.direct,
            detail="Upgrade to a version that satisfies all pip-audit fixes.",
        )
    return None


def _highest_version(versions: list[str]) -> str:
    return sorted(set(versions), key=_version_sort_key)[-1]


def _version_sort_key(version: str) -> tuple[int, Version | str]:
    try:
        return 0, Version(version)
    except InvalidVersion:
        return 1, version


def _replace_requirement_line(line: str, replacement_map: dict[str, str]) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return line
    match = re.match(r"^\s*([A-Za-z0-9_.-]+)", line)
    if not match:
        return line
    package_name = match.group(1).lower()
    replacement = replacement_map.get(package_name)
    if replacement is None:
        return line
    suffix = "\n" if line.endswith("\n") else ""
    return f"{replacement}{suffix}"
