from __future__ import annotations

from snake_guard.parsers.base import ManifestParser
from snake_guard.parsers.functions import (
    parse_poetry_lock,
    parse_pyproject,
    parse_requirement_specs,
    parse_requirements,
    parse_uv_lock,
)
from snake_guard.parsers.inventory import build_inventory, dedupe_inventory
from snake_guard.parsers.poetry_lock import PoetryLockParser
from snake_guard.parsers.pyproject import PyprojectParser
from snake_guard.parsers.registry import default_manifest_parsers
from snake_guard.parsers.requirements import RequirementsParser
from snake_guard.parsers.uv_lock import UvLockParser

__all__ = [
    "ManifestParser",
    "RequirementsParser",
    "PyprojectParser",
    "PoetryLockParser",
    "UvLockParser",
    "build_inventory",
    "dedupe_inventory",
    "default_manifest_parsers",
    "parse_requirements",
    "parse_requirement_specs",
    "parse_pyproject",
    "parse_poetry_lock",
    "parse_uv_lock",
]
