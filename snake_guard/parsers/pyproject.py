from __future__ import annotations

from pathlib import Path

from snake_guard.models import Dependency, DependencyType
from snake_guard.parsers.base import ManifestParser
from snake_guard.parsers.common import dependency_from_string, is_pinned

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib


class PyprojectParser(ManifestParser):
    filename = "pyproject.toml"

    def parse(self, path: Path) -> list[Dependency]:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        dependencies: list[Dependency] = []

        project = data.get("project", {})
        for entry in project.get("dependencies", []):
            dependency = dependency_from_string(entry, path.name)
            if dependency:
                dependencies.append(dependency)

        for group_entries in project.get("optional-dependencies", {}).values():
            for entry in group_entries:
                dependency = dependency_from_string(entry, path.name)
                if dependency:
                    dependencies.append(dependency)

        poetry = data.get("tool", {}).get("poetry", {})
        dependencies.extend(self._dependencies_from_poetry_mapping(poetry.get("dependencies", {}), path.name))

        poetry_groups = poetry.get("group", {})
        for group in poetry_groups.values():
            if not isinstance(group, dict):
                continue
            dependencies.extend(self._dependencies_from_poetry_mapping(group.get("dependencies", {}), path.name))

        dependency_groups = data.get("dependency-groups", {})
        for group_entries in dependency_groups.values():
            for entry in group_entries:
                if isinstance(entry, str):
                    dependency = dependency_from_string(entry, path.name)
                    if dependency:
                        dependencies.append(dependency)
        return dependencies

    def _dependencies_from_poetry_mapping(self, mapping: object, source_file: str) -> list[Dependency]:
        if not isinstance(mapping, dict):
            return []
        dependencies: list[Dependency] = []
        for name, value in mapping.items():
            if name.lower() == "python":
                continue
            dependencies.append(self._dependency_from_poetry(name, value, source_file))
        return dependencies

    def _dependency_from_poetry(self, name: str, value: object, source_file: str) -> Dependency:
        specifier: str | None = None
        markers: str | None = None
        extras: list[str] = []
        if isinstance(value, str):
            specifier = value
        elif isinstance(value, dict):
            specifier = str(value.get("version") or "")
            if isinstance(value.get("markers"), str):
                markers = value["markers"]
            if isinstance(value.get("extras"), list):
                extras = [str(item) for item in value["extras"]]
        return Dependency(
            name=name,
            version_specifier=specifier or None,
            source_file=source_file,
            dependency_type=DependencyType.DIRECT,
            pinned=is_pinned(specifier),
            hash_pinned=False,
            extras=extras,
            markers=markers,
        )

