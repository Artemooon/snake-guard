from __future__ import annotations

from pathlib import Path

from snake_guard.models import Dependency
from snake_guard.parsers.common import parse_requirement_line
from snake_guard.parsers.poetry_lock import PoetryLockParser
from snake_guard.parsers.pyproject import PyprojectParser
from snake_guard.parsers.requirements import RequirementsParser
from snake_guard.parsers.uv_lock import UvLockParser


def parse_requirements(path: Path) -> list[Dependency]:
    return RequirementsParser().parse(path)


def parse_requirement_specs(entries: list[str], source_name: str = "cli") -> list[Dependency]:
    dependencies: list[Dependency] = []
    for entry in entries:
        dependency = parse_requirement_line(entry, source_name)
        if dependency is not None:
            dependencies.append(dependency)
    return dependencies


def parse_pyproject(path: Path) -> list[Dependency]:
    return PyprojectParser().parse(path)


def parse_poetry_lock(path: Path) -> list[Dependency]:
    return PoetryLockParser().parse(path)


def parse_uv_lock(path: Path) -> list[Dependency]:
    return UvLockParser().parse(path)

