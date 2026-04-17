from __future__ import annotations

import difflib
import re
import subprocess
from pathlib import Path
from typing import Callable

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
from snake_guard.parsers.common import parse_requirement_entry


def build_fix_plan(
    root: Path,
    result: ScanResult,
    apply: bool = False,
    progress_callback: Callable[[str], None] | None = None,
) -> tuple[FixPlan, str | None]:
    requirements_path = root / "requirements.txt"
    pyproject_path = root / "pyproject.toml"
    requirements_direct_by_name = {
        dependency.name.lower(): dependency
        for dependency in result.inventory.direct_dependencies()
        if dependency.source_file == "requirements.txt"
    }
    pyproject_direct_by_name = {
        dependency.name.lower(): dependency
        for dependency in result.inventory.direct_dependencies()
        if dependency.source_file == "pyproject.toml"
    }
    lock_commands = _lock_commands(root)

    actions: list[FixAction] = []
    recommendations = _pinning_recommendations(result.inventory.dependencies)
    warnings: list[str] = []
    requirements_replacement_map: dict[str, str] = {}
    pyproject_replacement_map: dict[str, str] = {}

    for package in result.packages:
        plan_action = _action_for_package(package)
        if plan_action is None:
            continue
        _log_progress(
            progress_callback,
            _progress_message_for_action(
                plan_action.action, package.package, plan_action.target_version
            ),
        )
        if plan_action.action == "upgrade":
            package_key = package.package.lower()
            requirements_dependency = requirements_direct_by_name.get(package_key)
            pyproject_dependency = pyproject_direct_by_name.get(package_key)
            if requirements_dependency is not None:
                requirements_replacement_map[package_key] = (
                    f"{package.package}=={plan_action.target_version}"
                )
                plan_action.manifest = "requirements.txt"
            elif pyproject_dependency is not None and lock_commands:
                pyproject_replacement_map[package_key] = (
                    f"=={plan_action.target_version}"
                )
                plan_action.manifest = "pyproject.toml"
            else:
                supported_manifests = "requirements.txt direct dependencies or pyproject.toml projects with poetry.lock/uv.lock"
                warnings.append(
                    f"{package.package}: safe upgrade found, but automatic edits are only implemented for {supported_manifests}"
                )
                actions.append(plan_action)
                continue
        actions.append(plan_action)

    diffs: list[str] = []
    lock_originals = {
        path: path.read_text(encoding="utf-8")
        for _, path in lock_commands
        if path.exists()
    }
    pyproject_changed = False

    if requirements_replacement_map and requirements_path.exists():
        original = requirements_path.read_text(encoding="utf-8").splitlines(
            keepends=True
        )
        updated = [
            _replace_requirement_line(line, requirements_replacement_map)
            for line in original
        ]
        if original != updated:
            diffs.append(_diff_for_lines(original, updated, "requirements.txt"))
            if apply:
                requirements_path.write_text("".join(updated), encoding="utf-8")
                for action in actions:
                    if (
                        action.manifest == "requirements.txt"
                        and action.action == "upgrade"
                    ):
                        action.applied = True

    if pyproject_replacement_map and pyproject_path.exists():
        original = pyproject_path.read_text(encoding="utf-8").splitlines(keepends=True)
        updated = _replace_pyproject_dependencies(original, pyproject_replacement_map)
        if original != updated:
            pyproject_changed = True
            diffs.append(_diff_for_lines(original, updated, "pyproject.toml"))
            if apply:
                pyproject_path.write_text("".join(updated), encoding="utf-8")
                for action in actions:
                    if (
                        action.manifest == "pyproject.toml"
                        and action.action == "upgrade"
                    ):
                        action.applied = True

    if pyproject_replacement_map and lock_commands:
        if apply and pyproject_changed:
            for command, lock_path in lock_commands:
                _log_progress(progress_callback, f"fix: refreshing {lock_path.name}")
                lock_result = _run_lock_command(root, command)
                if lock_result is not None:
                    warnings.append(lock_result)
                    continue
                if lock_path.exists():
                    original_lock = lock_originals.get(lock_path, "")
                    updated_lock = lock_path.read_text(encoding="utf-8")
                    if original_lock != updated_lock:
                        diffs.append(
                            _diff_for_lines(
                                original_lock.splitlines(keepends=True),
                                updated_lock.splitlines(keepends=True),
                                lock_path.name,
                            )
                        )
        elif not apply and pyproject_changed:
            for command, _ in lock_commands:
                warnings.append(
                    f"After applying pyproject.toml changes, run: {' '.join(command)}"
                )

    if any(action.action == "manual_review" for action in actions):
        warnings.extend(post_compromise_hygiene())

    diff = "\n".join(diffs) if diffs else None
    return (
        FixPlan(actions=actions, recommendations=recommendations, warnings=warnings),
        diff,
    )


def _pinning_recommendations(dependencies: list[Dependency]) -> list[FixRecommendation]:
    recommendations: list[FixRecommendation] = []
    seen: set[tuple[str, str | None]] = set()
    resolved_versions = {
        dependency.name.lower(): dependency.resolved_version
        for dependency in dependencies
        if dependency.dependency_type == DependencyType.RESOLVED
        and dependency.resolved_version
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
                recommended_specifier=_recommended_pin_specifier(
                    resolved_versions.get(dependency.name.lower())
                ),
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


def _log_progress(
    progress_callback: Callable[[str], None] | None, message: str
) -> None:
    if progress_callback is not None:
        progress_callback(message)


def _action_for_package(package: PackageRisk) -> FixAction | None:
    suspicious = any(
        finding.type == FindingType.MALWARE_HEURISTIC for finding in package.findings
    )
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


def _progress_message_for_action(
    action: str, package: str, target_version: str | None
) -> str:
    if action == "upgrade":
        if target_version:
            return f"fix: upgrading {package} to {target_version}"
        return f"fix: upgrading {package}"
    if action == "manual_review":
        return f"fix: manual review required for {package}"
    return f"fix: processing {package}"


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


def _lock_commands(root: Path) -> list[tuple[list[str], Path]]:
    commands: list[tuple[list[str], Path]] = []
    poetry_lock = root / "poetry.lock"
    uv_lock = root / "uv.lock"
    if poetry_lock.exists():
        commands.append((["poetry", "lock"], poetry_lock))
    if uv_lock.exists():
        commands.append((["uv", "lock"], uv_lock))
    return commands


def _run_lock_command(root: Path, command: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        return f"Could not refresh lock file because {command[0]!r} is not installed."
    except subprocess.TimeoutExpired:
        return f"Could not refresh lock file because {' '.join(command)} timed out."

    if completed.returncode == 0:
        return None
    detail = (completed.stderr or completed.stdout).strip()
    if detail:
        detail = detail.splitlines()[-1]
        return f"Could not refresh lock file with {' '.join(command)}: {detail}"
    return f"Could not refresh lock file with {' '.join(command)}: exited with {completed.returncode}"


def _diff_for_lines(original: list[str], updated: list[str], filename: str) -> str:
    return "".join(
        difflib.unified_diff(original, updated, fromfile=filename, tofile=filename)
    )


def _replace_pyproject_dependencies(
    lines: list[str], replacement_map: dict[str, str]
) -> list[str]:
    updated: list[str] = []
    section: str | None = None
    array_key: str | None = None
    array_allowed = False

    for line in lines:
        stripped = line.strip()
        header_match = re.match(r"^\s*\[([^\]]+)\]\s*(?:#.*)?$", line)
        if header_match and array_key is None:
            section = header_match.group(1)

        if array_key is not None:
            if array_allowed:
                line = _replace_pyproject_array_dependency(line, replacement_map)
            if re.match(r"^\s*\]", stripped):
                array_key = None
                array_allowed = False
            updated.append(line)
            continue

        array_match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*=\s*\[\s*(?:#.*)?$", line)
        if array_match:
            array_key = array_match.group(1)
            array_allowed = _dependency_array_is_allowed(section, array_key)
            updated.append(line)
            continue

        if _poetry_dependency_section(section):
            line = _replace_poetry_dependency_line(line, replacement_map)
        updated.append(line)

    return updated


def _dependency_array_is_allowed(section: str | None, array_key: str) -> bool:
    if section == "project" and array_key == "dependencies":
        return True
    if section == "project.optional-dependencies":
        return True
    if section == "dependency-groups":
        return True
    return False


def _poetry_dependency_section(section: str | None) -> bool:
    if section == "tool.poetry.dependencies":
        return True
    return bool(
        section
        and section.startswith("tool.poetry.group.")
        and section.endswith(".dependencies")
    )


def _replace_poetry_dependency_line(line: str, replacement_map: dict[str, str]) -> str:
    match = re.match(
        r"^(?P<prefix>\s*([A-Za-z0-9_.-]+|\"[^\"]+\")\s*=\s*)(?P<value>.+?)(?P<suffix>\r?\n?)$",
        line,
    )
    if not match:
        return line

    raw_name = match.group(2).strip('"')
    if raw_name.lower() == "python":
        return line
    replacement = replacement_map.get(raw_name.lower())
    if replacement is None:
        return line

    value = match.group("value")
    if value.lstrip().startswith("{"):
        replaced = re.sub(
            r'version\s*=\s*"[^"]*"', f'version = "{replacement}"', value, count=1
        )
        if replaced == value:
            return line
        return f"{match.group('prefix')}{replaced}{match.group('suffix')}"

    comment = ""
    value_without_comment = value
    if " #" in value:
        value_without_comment, comment = value.split(" #", 1)
        comment = f" #{comment}"
    quote_match = re.match(r"^(\s*)\"[^\"]*\"(\s*)$", value_without_comment)
    if not quote_match:
        return line
    return (
        f"{match.group('prefix')}{quote_match.group(1)}\"{replacement}\""
        f"{quote_match.group(2)}{comment}{match.group('suffix')}"
    )


def _replace_pyproject_array_dependency(
    line: str, replacement_map: dict[str, str]
) -> str:
    match = re.match(
        r'^(?P<indent>\s*)"(?P<entry>[^"]+)"(?P<trailing>,?\s*(?:#.*)?)(?P<suffix>\r?\n?)$',
        line,
    )
    if not match:
        return line

    name, _specifier, extras, markers = parse_requirement_entry(match.group("entry"))
    if not name:
        return line
    replacement = replacement_map.get(name.lower())
    if replacement is None:
        return line

    extras_text = f"[{','.join(extras)}]" if extras else ""
    markers_text = f"; {markers}" if markers else ""
    return (
        f'{match.group("indent")}"{name}{extras_text}{replacement}{markers_text}"'
        f'{match.group("trailing")}{match.group("suffix")}'
    )
