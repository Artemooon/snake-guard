from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class DependencyType(str, Enum):
    DIRECT = "direct"
    RESOLVED = "resolved"


class FindingType(str, Enum):
    KNOWN_VULN = "known_vuln"
    MALWARE_HEURISTIC = "malware_heuristic"
    MISSING_PROVENANCE = "missing_provenance"
    MISSING_TRUSTED_PUBLISHING = "missing_trusted_publishing"


@dataclass(slots=True)
class Dependency:
    name: str
    version_specifier: str | None = None
    resolved_version: str | None = None
    source_file: str | None = None
    dependency_type: DependencyType = DependencyType.DIRECT
    pinned: bool = False
    hash_pinned: bool = False
    extras: list[str] = field(default_factory=list)
    markers: str | None = None

    def __post_init__(self) -> None:
        self.dependency_type = DependencyType(self.dependency_type)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["dependency_type"] = self.dependency_type.value
        return payload


@dataclass(slots=True)
class Inventory:
    root: Path
    dependencies: list[Dependency] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def direct_dependencies(self) -> list[Dependency]:
        return [dependency for dependency in self.dependencies if dependency.dependency_type == DependencyType.DIRECT]

    def resolved_dependencies(self) -> list[Dependency]:
        return [dependency for dependency in self.dependencies if dependency.dependency_type == DependencyType.RESOLVED]

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "manifests": self.manifests,
            "warnings": self.warnings,
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
        }


@dataclass(slots=True)
class Finding:
    type: FindingType
    source: str
    identifier: str | None = None
    detail: str | None = None
    rule: str | None = None
    severity: str | None = None
    fixed_versions: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.type = FindingType(self.type)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["type"] = self.type.value
        return payload


@dataclass(slots=True)
class PackageRisk:
    package: str
    installed_version: str | None
    risk_level: str = "info"
    findings: list[Finding] = field(default_factory=list)
    recommended_action: str = "manual_review"
    direct: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "installed_version": self.installed_version,
            "risk_level": self.risk_level,
            "recommended_action": self.recommended_action,
            "direct": self.direct,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(slots=True)
class EngineIssue:
    engine: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EngineStatus:
    engine: str
    status: str
    findings_count: int = 0
    issues_count: int = 0
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    inventory: Inventory
    packages: list[PackageRisk] = field(default_factory=list)
    issues: list[EngineIssue] = field(default_factory=list)
    engine_statuses: list[EngineStatus] = field(default_factory=list)

    def suspicious_packages(self) -> list[PackageRisk]:
        return [
            package
            for package in self.packages
            if any(finding.type == FindingType.MALWARE_HEURISTIC for finding in package.findings)
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "inventory": self.inventory.to_dict(),
            "packages": [package.to_dict() for package in self.packages],
            "issues": [issue.to_dict() for issue in self.issues],
            "engine_statuses": [status.to_dict() for status in self.engine_statuses],
        }


@dataclass(slots=True)
class FixAction:
    package: str
    action: str
    target_version: str | None = None
    manifest: str | None = None
    direct: bool = False
    applied: bool = False
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FixRecommendation:
    package: str
    recommendation: str
    manifest: str | None = None
    current_specifier: str | None = None
    recommended_specifier: str | None = None
    direct: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FixPlan:
    actions: list[FixAction] = field(default_factory=list)
    recommendations: list[FixRecommendation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "actions": [action.to_dict() for action in self.actions],
            "recommendations": [recommendation.to_dict() for recommendation in self.recommendations],
            "warnings": self.warnings,
        }


@dataclass(slots=True)
class SandboxObservation:
    kind: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SandboxReport:
    package: str
    import_name: str
    image: str
    container_runtime: str
    network_enabled: bool
    allowed_by_policy: bool
    policy_reason: str
    exit_code: int | None = None
    install_succeeded: bool = False
    import_succeeded: bool = False
    status: str = "not_run"
    summary: str = ""
    recommended_action: str = ""
    stdout: str = ""
    stderr: str = ""
    observations: list[SandboxObservation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "import_name": self.import_name,
            "image": self.image,
            "container_runtime": self.container_runtime,
            "network_enabled": self.network_enabled,
            "allowed_by_policy": self.allowed_by_policy,
            "policy_reason": self.policy_reason,
            "exit_code": self.exit_code,
            "install_succeeded": self.install_succeeded,
            "import_succeeded": self.import_succeeded,
            "status": self.status,
            "summary": self.summary,
            "recommended_action": self.recommended_action,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "observations": [observation.to_dict() for observation in self.observations],
        }


@dataclass(slots=True)
class InstallStageReport:
    stage: str
    ok: bool
    detail: str
    exit_code: int | None = None
    payload: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class InstallPackageDecision:
    package: str
    action: str
    reason: str
    risk_level: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class InstallReport:
    root: str
    manager: str
    command: list[str]
    dry_run: bool = False
    planned_sandbox_packages: list[InstallPackageDecision] = field(default_factory=list)
    planned_direct_install_packages: list[InstallPackageDecision] = field(default_factory=list)
    stages: list[InstallStageReport] = field(default_factory=list)
    sandbox_reports: list[SandboxReport] = field(default_factory=list)
    install_stdout: str = ""
    install_stderr: str = ""
    install_exit_code: int | None = None

    def succeeded(self) -> bool:
        return all(stage.ok for stage in self.stages)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "manager": self.manager,
            "command": self.command,
            "dry_run": self.dry_run,
            "planned_sandbox_packages": [item.to_dict() for item in self.planned_sandbox_packages],
            "planned_direct_install_packages": [item.to_dict() for item in self.planned_direct_install_packages],
            "stages": [stage.to_dict() for stage in self.stages],
            "sandbox_reports": [report.to_dict() for report in self.sandbox_reports],
            "install_stdout": self.install_stdout,
            "install_stderr": self.install_stderr,
            "install_exit_code": self.install_exit_code,
            "succeeded": self.succeeded(),
        }
