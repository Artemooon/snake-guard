from __future__ import annotations

import re

from snake_guard.models import Dependency, DependencyType

REQ_SPLIT_RE = re.compile(r"(?P<name>[A-Za-z0-9_.-]+)(?P<extras>\[[^\]]+\])?(?P<specifier>.*)")
PIN_RE = re.compile(r"^\s*==\s*([^\s;]+)\s*$")
BARE_VERSION_RE = re.compile(r"^\s*[0-9]+(?:[A-Za-z0-9_.!+-]*)\s*$")
NAME_ONLY_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def dependency_from_string(entry: str, source_file: str) -> Dependency | None:
    name, specifier, extras, markers = parse_requirement_entry(entry)
    if not name:
        return None
    return Dependency(
        name=name,
        version_specifier=specifier,
        source_file=source_file,
        dependency_type=DependencyType.DIRECT,
        pinned=is_pinned(specifier),
        hash_pinned=False,
        extras=extras,
        markers=markers,
    )


def dependencies_from_lock_packages(packages: object, source_file: str) -> list[Dependency]:
    if not isinstance(packages, list):
        return []
    dependencies: list[Dependency] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if not name or not version:
            continue
        dependencies.append(
            Dependency(
                name=name,
                resolved_version=version,
                source_file=source_file,
                dependency_type=DependencyType.RESOLVED,
                pinned=True,
                hash_pinned=False,
            )
        )
    return dependencies


def parse_requirement_line(raw_line: str, source_file: str) -> Dependency | None:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith(("-r ", "--requirement", "-c ", "--constraint")):
        return None
    hash_pinned = "--hash=" in line
    line = strip_inline_comment(line)
    name, specifier, extras, markers = parse_requirement_entry(line)
    if not name:
        return None
    return Dependency(
        name=name,
        version_specifier=specifier,
        source_file=source_file,
        dependency_type=DependencyType.DIRECT,
        pinned=is_pinned(specifier),
        hash_pinned=hash_pinned,
        extras=extras,
        markers=markers,
    )


def parse_requirement_entry(entry: str) -> tuple[str | None, str | None, list[str], str | None]:
    markers: str | None = None
    requirement = entry.strip()
    if ";" in requirement:
        requirement, markers = [part.strip() for part in requirement.split(";", 1)]
    match = REQ_SPLIT_RE.match(requirement)
    if not match:
        return None, None, [], markers
    name = match.group("name")
    extras_text = match.group("extras")
    extras = extras_text[1:-1].split(",") if extras_text else []
    specifier = match.group("specifier").strip() or None
    if NAME_ONLY_RE.fullmatch(requirement):
        specifier = None
    return name, specifier, [extra.strip() for extra in extras if extra.strip()], markers


def strip_inline_comment(line: str) -> str:
    if " #" not in line:
        return line
    return line.split(" #", 1)[0].rstrip()


def is_pinned(specifier: str | None) -> bool:
    if not specifier:
        return False
    return PIN_RE.match(specifier) is not None or BARE_VERSION_RE.match(specifier) is not None


def pinned_version_from_specifier(specifier: str | None) -> str | None:
    if not specifier:
        return None
    pin_match = PIN_RE.match(specifier)
    if pin_match:
        return pin_match.group(1).strip()
    if BARE_VERSION_RE.match(specifier):
        return specifier.strip()
    return None
