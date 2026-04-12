from __future__ import annotations

from pathlib import Path

from snake_guard.models import Dependency, DependencyType, Inventory
from snake_guard.parsers.base import ManifestParser
from snake_guard.parsers.registry import default_manifest_parsers


def build_inventory(root: Path, parsers: list[ManifestParser] | None = None) -> Inventory:
    inventory = Inventory(root=root)
    for parser in parsers or default_manifest_parsers():
        path = root / parser.filename
        if not path.exists():
            continue
        inventory.manifests.append(parser.filename)
        try:
            inventory.dependencies.extend(parser.parse(path))
        except Exception as exc:  # pragma: no cover - defensive path
            inventory.warnings.append(f"Failed to parse {parser.filename}: {exc}")
    dedupe_inventory(inventory)
    return inventory


def dedupe_inventory(inventory: Inventory) -> None:
    seen: set[tuple[str, str, str | None, str | None]] = set()
    unique: list[Dependency] = []
    for dependency in inventory.dependencies:
        key = (
            dependency.name.lower(),
            dependency.dependency_type,
            dependency.source_file,
            dependency.resolved_version or dependency.version_specifier,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(dependency)
    inventory.dependencies = sorted(
        unique,
        key=lambda dep: (dep.dependency_type != DependencyType.DIRECT, dep.name.lower(), dep.source_file or ""),
    )

