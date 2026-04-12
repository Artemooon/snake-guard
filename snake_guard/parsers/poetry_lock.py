from __future__ import annotations

from pathlib import Path

from snake_guard.models import Dependency
from snake_guard.parsers.base import ManifestParser
from snake_guard.parsers.common import dependencies_from_lock_packages

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib


class PoetryLockParser(ManifestParser):
    filename = "poetry.lock"

    def parse(self, path: Path) -> list[Dependency]:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return dependencies_from_lock_packages(data.get("package", []), path.name)

