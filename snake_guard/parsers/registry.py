from __future__ import annotations

from snake_guard.parsers.base import ManifestParser
from snake_guard.parsers.poetry_lock import PoetryLockParser
from snake_guard.parsers.pyproject import PyprojectParser
from snake_guard.parsers.requirements import RequirementsParser
from snake_guard.parsers.uv_lock import UvLockParser


def default_manifest_parsers() -> list[ManifestParser]:
    return [RequirementsParser(), PyprojectParser(), PoetryLockParser(), UvLockParser()]

