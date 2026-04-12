from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

from snake_guard.models import InstallPackageDecision, InstallReport, InstallStageReport, ScanResult
from snake_guard.parsers import parse_requirement_specs, parse_requirements
from snake_guard.sandbox import SandboxDockerOptions, sandbox_package
from snake_guard.service import scan_dependencies, scan_project


def install_project(
    root: Path,
    *,
    manager: str = "auto",
    requirement: Path | None = None,
    packages: list[str] | None = None,
    installer_args: list[str] | None = None,
    allow_network: bool = True,
    pull_image: bool = True,
    sandbox_runtime: str = "docker",
    sandbox_image: str = "python:3.11-slim",
    sandbox_docker_options: SandboxDockerOptions | None = None,
    force_sandbox: bool = False,
    sandbox_risky: bool = True,
    continue_on_sandbox_failure: bool = False,
    dry_run: bool = False,
    progress_callback: Callable[[str], None] | None = None,
) -> InstallReport:
    resolved_root = root.resolve()
    _log_progress(progress_callback, "install: detecting manager")
    selected_manager = _detect_manager(resolved_root, manager, requirement, packages or [])
    command = _build_install_command(
        resolved_root,
        manager=selected_manager,
        requirement=requirement,
        packages=packages or [],
        installer_args=installer_args or [],
    )
    report = InstallReport(
        root=str(resolved_root),
        manager=selected_manager,
        command=command,
        dry_run=dry_run,
    )
    report.stages.append(
        InstallStageReport(
            stage="detect",
            ok=True,
            detail=f"detected manager: {selected_manager}",
            payload={"manager": selected_manager, "command": command},
        )
    )

    _log_progress(progress_callback, "install: loading dependency scan")
    scan_result = _scan_install_target(resolved_root, requirement, packages or [], progress_callback=progress_callback)
    risky_packages = _risky_packages(scan_result)
    direct_packages = _direct_install_packages(scan_result)
    risky_names = {package.package.lower() for package in risky_packages}
    report.planned_sandbox_packages = [
        InstallPackageDecision(
            package=package.package,
            action="sandbox",
            reason="package is high or critical risk and will be sandboxed before install",
            risk_level=package.risk_level,
        )
        for package in risky_packages
    ]
    report.planned_direct_install_packages = [
        InstallPackageDecision(
            package=package.package,
            action="install",
            reason="package is not currently marked high or critical risk",
            risk_level=package.risk_level,
        )
        for package in direct_packages
        if package.package.lower() not in risky_names
    ]
    report.stages.append(
        InstallStageReport(
            stage="scan",
            ok=True,
            detail=f"scan completed, found {len(risky_packages)} high/critical package(s)",
            payload=scan_result.to_dict(),
        )
    )

    if dry_run:
        _log_progress(progress_callback, "install: loading dry-run plan")
        report.stages.append(
            InstallStageReport(
                stage="plan",
                ok=True,
                detail="dry run only; no sandbox or installer commands were executed",
                payload={
                    "sandbox_packages": [item.to_dict() for item in report.planned_sandbox_packages],
                    "direct_install_packages": [item.to_dict() for item in report.planned_direct_install_packages],
                },
            )
        )
        return report

    if sandbox_risky and risky_packages:
        _log_progress(progress_callback, "install: loading sandbox checks")
        sandbox_ok = True
        for index, package in enumerate(risky_packages, start=1):
            _log_progress(progress_callback, f"install: sandboxing {package.package} ({index}/{len(risky_packages)})")
            sandbox_report = sandbox_package(
                resolved_root,
                package.package,
                force=force_sandbox or bool((packages or []) or requirement is not None),
                allow_network=allow_network,
                pull_image=pull_image,
                image=sandbox_image,
                runtime=sandbox_runtime,
                docker_options=sandbox_docker_options,
            )
            report.sandbox_reports.append(sandbox_report)
            current_ok = sandbox_report.allowed_by_policy and sandbox_report.install_succeeded and sandbox_report.import_succeeded
            sandbox_ok = sandbox_ok and current_ok
        detail = f"sandboxed {len(report.sandbox_reports)} risky package(s)"
        if not sandbox_ok and not continue_on_sandbox_failure:
            report.stages.append(
                InstallStageReport(
                    stage="sandbox",
                    ok=False,
                    detail=f"{detail}; blocking install because at least one sandbox run failed",
                )
            )
            return report
        report.stages.append(
            InstallStageReport(
                stage="sandbox",
                ok=sandbox_ok or continue_on_sandbox_failure,
                detail=detail if sandbox_ok else f"{detail}; proceeding because --continue-on-sandbox-failure is enabled",
                payload={"count": len(report.sandbox_reports)},
            )
            )
    else:
        _log_progress(progress_callback, "install: loading dependency installer")
        report.stages.append(
            InstallStageReport(
                stage="sandbox",
                ok=True,
                detail="no sandbox step was required",
            )
        )

    _log_progress(progress_callback, "install: running dependency installer")
    install_run = _run_install(command, resolved_root)
    report.install_exit_code = install_run.returncode
    report.install_stdout = install_run.stdout
    report.install_stderr = install_run.stderr
    report.stages.append(
        InstallStageReport(
            stage="install",
            ok=install_run.returncode == 0,
            detail="dependency installer finished" if install_run.returncode == 0 else "dependency installer failed",
            exit_code=install_run.returncode,
        )
    )
    if install_run.returncode != 0:
        return report

    _log_progress(progress_callback, "install: loading verification scan")
    verify_result = scan_project(resolved_root, progress_callback=progress_callback)
    verified = not verify_result.suspicious_packages() and not any(
        package.risk_level in {"high", "critical"} for package in verify_result.packages
    )
    report.stages.append(
        InstallStageReport(
            stage="verify",
            ok=verified,
            detail="verification passed" if verified else "verification found high or critical risks after install",
            payload=verify_result.to_dict(),
        )
    )
    return report


def _log_progress(progress_callback: Callable[[str], None] | None, message: str) -> None:
    if progress_callback is not None:
        progress_callback(message)


def _detect_manager(root: Path, manager: str, requirement: Path | None, packages: list[str]) -> str:
    if manager != "auto":
        return manager
    if packages:
        return "pip"
    if requirement is not None or (root / "requirements.txt").exists():
        return "pip"
    if (root / "poetry.lock").exists():
        return "poetry"
    if (root / "uv.lock").exists():
        return "uv"
    if (root / "pyproject.toml").exists():
        return "uv"
    raise ValueError(
        "Could not detect an installer. Provide --manager, pass --package or -r/--requirement, "
        "or run inside a project with requirements.txt, poetry.lock, uv.lock, or pyproject.toml."
    )


def _build_install_command(
    root: Path,
    *,
    manager: str,
    requirement: Path | None,
    packages: list[str],
    installer_args: list[str],
) -> list[str]:
    if manager == "pip":
        command = _pip_install_command(root, requirement, packages)
    elif manager == "poetry":
        command = ["poetry", "add", *packages] if packages else ["poetry", "install"]
    elif manager == "uv":
        command = ["uv", "add", *packages] if packages else ["uv", "sync"]
    else:
        raise ValueError(f"Unsupported manager: {manager}")
    return [*command, *installer_args]


def _pip_install_command(root: Path, requirement: Path | None, packages: list[str]) -> list[str]:
    prefix = [sys.executable, "-m", "pip", "install"]
    if packages:
        return [*prefix, *packages]
    target = requirement or ((root / "requirements.txt") if (root / "requirements.txt").exists() else None)
    if target is not None:
        return [*prefix, "-r", str(target)]
    return [*prefix, "."]


def _run_install(command: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    executable = shutil.which(command[0])
    if executable is None:
        return subprocess.CompletedProcess(
            args=command,
            returncode=127,
            stdout="",
            stderr=f"{command[0]} is not installed or not on PATH",
        )
    adjusted_command = [executable, *command[1:]]
    try:
        return subprocess.run(
            adjusted_command,
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return subprocess.CompletedProcess(
            args=adjusted_command,
            returncode=126,
            stdout="",
            stderr=str(exc),
        )


def _risky_packages(result: ScanResult):
    return [package for package in result.packages if package.risk_level in {"high", "critical"}]


def _direct_install_packages(result: ScanResult):
    return [package for package in result.packages if package.direct]


def _scan_install_target(
    root: Path,
    requirement: Path | None,
    packages: list[str],
    progress_callback: Callable[[str], None] | None = None,
) -> ScanResult:
    if packages:
        dependencies = parse_requirement_specs(packages, source_name="cli")
        return scan_dependencies(root, dependencies, manifests=["cli"], progress_callback=progress_callback)
    if requirement is not None:
        dependencies = parse_requirements(requirement)
        return scan_dependencies(root, dependencies, manifests=[requirement.name], progress_callback=progress_callback)
    return scan_project(root, progress_callback=progress_callback)
