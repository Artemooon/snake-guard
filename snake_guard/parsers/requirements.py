from __future__ import annotations

from pathlib import Path

from snake_guard.models import Dependency
from snake_guard.parsers.base import ManifestParser
from snake_guard.parsers.common import parse_requirement_line


class RequirementsParser(ManifestParser):
    filename = "requirements.txt"

    def parse(self, path: Path) -> list[Dependency]:
        dependencies: list[Dependency] = []
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            dependency = parse_requirement_line(raw_line, path.name)
            if dependency is not None:
                dependencies.append(dependency)
        return dependencies

