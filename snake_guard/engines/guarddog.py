from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import shutil
import subprocess

from snake_guard.engines.base import MAX_EXTERNAL_WORKERS, EngineResult, ProgressCallback, ScanEngine
from snake_guard.models import Dependency, DependencyType, EngineIssue, Finding, FindingType


class GuarddogEngine(ScanEngine):
    name = "guarddog"

    def run(
        self,
        root: Path,
        dependencies: list[Dependency],
        progress_callback: ProgressCallback = None,
    ) -> EngineResult:
        executable = shutil.which(self.name)
        if executable is None:
            return {}, [EngineIssue(engine=self.name, message="guarddog is not installed")]

        findings_by_package: dict[str, list[Finding]] = defaultdict(list)
        issues: list[EngineIssue] = []
        temp_requirements = self._write_temp_requirements(dependencies)
        requirements = root / "requirements.txt"
        if temp_requirements is not None:
            if progress_callback is not None:
                progress_callback("guarddog: verifying generated dependency set")
            command = [executable, "pypi", "verify", temp_requirements.name, "--output-format=json"]
            completed = self._run_process(command, root)
            if isinstance(completed, EngineIssue):
                Path(temp_requirements.name).unlink(missing_ok=True)
                return {}, [completed]
            parsed = self._parse_output(completed.stdout)
            Path(temp_requirements.name).unlink(missing_ok=True)
            return parsed, []
        if requirements.exists():
            if progress_callback is not None:
                progress_callback("guarddog: verifying requirements.txt")
            command = [executable, "pypi", "verify", str(requirements), "--output-format=json"]
            completed = self._run_process(command, root)
            if isinstance(completed, EngineIssue):
                return {}, [completed]
            return self._parse_output(completed.stdout), []

        direct_dependencies = [dependency for dependency in dependencies if dependency.dependency_type == DependencyType.DIRECT]
        if direct_dependencies:
            with ThreadPoolExecutor(max_workers=min(MAX_EXTERNAL_WORKERS, len(direct_dependencies))) as executor:
                future_map = {
                    executor.submit(
                        self._scan_dependency,
                        executable,
                        root,
                        dependency,
                        progress_callback,
                    ): dependency
                    for dependency in direct_dependencies
                }
                for future in as_completed(future_map):
                    dependency = future_map[future]
                    completed = future.result()
                    if isinstance(completed, EngineIssue):
                        issues.append(completed)
                        continue
                    package_findings = self._parse_output(completed.stdout)
                    findings_by_package[dependency.name.lower()].extend(package_findings.get(dependency.name.lower(), []))
        return findings_by_package, issues

    def _scan_dependency(
        self,
        executable: str,
        root: Path,
        dependency: Dependency,
        progress_callback: ProgressCallback = None,
    ) -> subprocess.CompletedProcess[str] | EngineIssue:
        if progress_callback is not None:
            progress_callback(f"guarddog: scanning {dependency.name}")
        command = [executable, "pypi", "scan", dependency.name, "--output-format=json"]
        completed = self._run_process(command, root)
        if progress_callback is not None:
            progress_callback(f"guarddog: finished {dependency.name}")
        return completed

    def _parse_output(self, output: str) -> dict[str, list[Finding]]:
        payload = json.loads(output or "{}")
        findings_by_package: dict[str, list[Finding]] = defaultdict(list)

        if isinstance(payload, dict) and "issues" in payload:
            package_name = str(payload.get("name") or "")
            issues = payload.get("issues", [])
            if not isinstance(issues, list):
                return findings_by_package
            for issue in issues:
                if not isinstance(issue, dict):
                    continue
                findings_by_package[package_name.lower()].append(self._issue_to_finding(issue))
            return findings_by_package

        if isinstance(payload, dict):
            for package_name, package_data in payload.items():
                if not isinstance(package_data, dict):
                    continue
                issues = package_data.get("issues", [])
                if not isinstance(issues, list):
                    continue
                for issue in issues:
                    if not isinstance(issue, dict):
                        continue
                    findings_by_package[package_name.lower()].append(self._issue_to_finding(issue))
        return findings_by_package

    def _issue_to_finding(self, issue: dict) -> Finding:
        return Finding(
            type=FindingType.MALWARE_HEURISTIC,
            source=self.name,
            identifier=issue.get("id"),
            detail=issue.get("message") or issue.get("description"),
            rule=issue.get("rule") or issue.get("location"),
            severity=str(issue.get("severity", "high")).lower(),
        )

