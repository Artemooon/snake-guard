from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from snake_guard.engines.base import EngineResult, ProgressCallback, ScanEngine
from snake_guard.models import Dependency, DependencyType, EngineIssue, Finding, FindingType


class PipAuditEngine(ScanEngine):
    name = "pip-audit"

    def run(
        self,
        root: Path,
        dependencies: list[Dependency],
        progress_callback: ProgressCallback = None,
    ) -> EngineResult:
        executable = shutil.which(self.name)
        if executable is None:
            return {}, [EngineIssue(engine=self.name, message="pip-audit is not installed")]
        if progress_callback is not None:
            progress_callback("pip-audit: running advisory scan")

        command = [executable, "--format=json", "--progress-spinner=off"]
        temp_requirements = self._write_audit_requirements(dependencies)
        requirements = root / "requirements.txt"
        pyproject = root / "pyproject.toml"
        if temp_requirements is not None:
            command.extend(["-r", temp_requirements.name])
            if self._requirements_are_exact_pins(Path(temp_requirements.name)):
                command.extend(["--no-deps", "--disable-pip"])
        elif requirements.exists():
            command.extend(["-r", str(requirements)])
        elif pyproject.exists():
            command.extend(["-P", str(pyproject)])

        try:
            completed = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            return {}, [EngineIssue(engine=self.name, message=f"Failed to execute pip-audit: {exc}")]
        finally:
            if temp_requirements is not None:
                Path(temp_requirements.name).unlink(missing_ok=True)

        if completed.returncode not in {0, 1} or self._has_execution_failure(completed):
            message = self._failure_message(completed)
            return {}, [EngineIssue(engine=self.name, message=message)]

        return self._parse_output(completed.stdout)

    def _requirements_are_exact_pins(self, path: Path) -> bool:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line and "==" not in line:
                return False
        return True

    def _write_audit_requirements(self, dependencies: list[Dependency]) -> tempfile.NamedTemporaryFile | None:
        resolved_dependencies = [
            dependency
            for dependency in dependencies
            if dependency.dependency_type == DependencyType.RESOLVED and dependency.resolved_version
        ]
        if not resolved_dependencies:
            return self._write_temp_requirements(dependencies)

        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False)
        for dependency in resolved_dependencies:
            handle.write(f"{dependency.name}=={dependency.resolved_version}\n")
        handle.flush()
        handle.close()
        return handle

    def _has_execution_failure(self, completed: subprocess.CompletedProcess[str]) -> bool:
        if completed.stdout.strip():
            return False
        stderr = completed.stderr.strip()
        return "Traceback " in stderr or "ERROR:" in stderr

    def _failure_message(self, completed: subprocess.CompletedProcess[str]) -> str:
        message = completed.stderr.strip() or completed.stdout.strip() or "pip-audit failed"
        if "NameResolutionError" in message or "Failed to resolve" in message:
            return "pip-audit could not reach the vulnerability service: DNS resolution failed"
        if "CERTIFICATE_VERIFY_FAILED" in message:
            return "pip-audit could not reach the vulnerability service: TLS certificate verification failed"
        if "Traceback " not in message:
            return message
        lines = [line.strip() for line in message.splitlines() if line.strip()]
        return lines[-1] if lines else "pip-audit failed"

    def _parse_output(self, output: str) -> EngineResult:
        try:
            payload = json.loads(output or "{}")
        except json.JSONDecodeError as exc:
            return {}, [EngineIssue(engine=self.name, message=f"Invalid JSON output: {exc}")]
        raw_dependencies = payload.get("dependencies", payload if isinstance(payload, list) else [])
        findings_by_package: dict[str, list[Finding]] = defaultdict(list)
        for package in raw_dependencies:
            name = package.get("name")
            if not name:
                continue
            for vulnerability in package.get("vulns", []):
                findings_by_package[name.lower()].append(self._finding_from_vulnerability(vulnerability))
        return findings_by_package, []

    def _finding_from_vulnerability(self, vulnerability: dict) -> Finding:
        return Finding(
            type=FindingType.KNOWN_VULN,
            source=self.name,
            identifier=vulnerability.get("id"),
            detail=vulnerability.get("description"),
            severity=self._severity_from_aliases(vulnerability),
            fixed_versions=list(vulnerability.get("fix_versions", [])),
        )

    def _severity_from_aliases(self, vulnerability: dict) -> str:
        aliases = vulnerability.get("aliases", [])
        if aliases:
            return "high"
        return "medium"
