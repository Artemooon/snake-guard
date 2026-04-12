from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
import subprocess
import tempfile
from typing import Callable

from snake_guard.models import Dependency, DependencyType, EngineIssue, Finding
from snake_guard.parsers.common import pinned_version_from_specifier

MAX_EXTERNAL_WORKERS = 8
EngineResult = tuple[dict[str, list[Finding]], list[EngineIssue]]
ProgressCallback = Callable[[str], None] | None


class ScanEngine(ABC):
    name: str

    @abstractmethod
    def run(
        self,
        root: Path,
        dependencies: list[Dependency],
        progress_callback: ProgressCallback = None,
    ) -> EngineResult:
        raise NotImplementedError

    def _run_process(self, command: list[str], root: Path) -> subprocess.CompletedProcess[str] | EngineIssue:
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            return EngineIssue(engine=command[0], message=f"Failed to execute {' '.join(command)}: {exc}")
        if completed.returncode not in {0, 1}:
            message = completed.stderr.strip() or completed.stdout.strip() or f"{command[0]} failed"
            return EngineIssue(engine=command[0], message=message)
        return completed

    def _write_temp_requirements(self, dependencies: list[Dependency]) -> tempfile.NamedTemporaryFile | None:
        direct_dependencies = [dependency for dependency in dependencies if dependency.dependency_type == DependencyType.DIRECT]
        if not direct_dependencies:
            return None
        resolved_versions = {
            dependency.name.lower(): dependency.resolved_version
            for dependency in dependencies
            if dependency.dependency_type == DependencyType.RESOLVED and dependency.resolved_version
        }
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False)
        for dependency in direct_dependencies:
            handle.write(f"{self._requirement_line(dependency, resolved_versions)}\n")
        handle.flush()
        handle.close()
        return handle

    def _requirement_line(self, dependency: Dependency, resolved_versions: dict[str, str]) -> str:
        name = dependency.name
        if dependency.extras:
            name += f"[{','.join(dependency.extras)}]"
        resolved_version = resolved_versions.get(dependency.name.lower())
        if resolved_version:
            return f"{name}=={resolved_version}"
        pinned_version = pinned_version_from_specifier(dependency.version_specifier)
        if pinned_version:
            return f"{name}=={pinned_version}"
        specifier = dependency.version_specifier or ""
        return f"{name}{specifier}"
