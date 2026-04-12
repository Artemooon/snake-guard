from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Sequence

from snake_guard.models import PackageRisk, SandboxObservation, SandboxReport
from snake_guard.service import scan_project


@dataclass(slots=True)
class SandboxDockerOptions:
    memory: str = "2g"
    cpus: str = "1.0"
    pids_limit: str = "128"
    tmpfs_size: str = "1g"
    user: str = "65534:65534"
    extra_args: list[str] = field(default_factory=list)


def sandbox_package(
    root: Path,
    package: str,
    *,
    force: bool = False,
    allow_network: bool = False,
    pull_image: bool = True,
    image: str = "python:3.11-slim",
    runtime: str = "docker",
    docker_options: SandboxDockerOptions | None = None,
) -> SandboxReport:
    return probe_package(
        root,
        package,
        force=force,
        allow_network=allow_network,
        pull_image=pull_image,
        image=image,
        runtime=runtime,
        docker_options=docker_options,
    )


def probe_package(
    root: Path,
    package: str,
    *,
    force: bool = False,
    allow_network: bool = False,
    pull_image: bool = True,
    image: str = "python:3.11-slim",
    runtime: str = "docker",
    docker_options: SandboxDockerOptions | None = None,
) -> SandboxReport:
    docker_options = docker_options or SandboxDockerOptions()
    executable = shutil.which(runtime)
    print("sandbox executable: ", executable)
    if executable is None:
        return SandboxReport(
            package=package,
            import_name=_guess_import_name(package),
            image=image,
            container_runtime=runtime,
            network_enabled=allow_network,
            allowed_by_policy=False,
            policy_reason=f"{runtime} is not installed or not on PATH",
            status="runtime_missing",
            summary=f"{runtime} was not found, so the sandbox did not run.",
            recommended_action=f"Install {runtime} or pass --runtime with another container runtime.",
            observations=[SandboxObservation(kind="runtime_missing", detail=f"{runtime} executable was not found")],
        )

    risk = _find_package_risk(root, package)
    allowed_by_policy, policy_reason = _sandbox_policy(risk, package, force)
    report = SandboxReport(
        package=package,
        import_name=_guess_import_name(package),
        image=image,
        container_runtime=runtime,
        network_enabled=allow_network,
        allowed_by_policy=allowed_by_policy,
        policy_reason=policy_reason,
    )
    if risk is not None:
        report.observations.append(
            SandboxObservation(
                kind="policy_input",
                detail=f"scan risk={risk.risk_level} recommended_action={risk.recommended_action}",
            )
        )
    if not allowed_by_policy:
        report.observations.append(SandboxObservation(kind="policy_block", detail=policy_reason))
        _finalize_probe_report(report)
        return report

    command = _docker_probe_command(
        executable=executable,
        package=package,
        import_name=report.import_name,
        image=image,
        allow_network=allow_network,
        pull_image=pull_image,
        docker_options=docker_options,
    )
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        report.policy_reason = f"failed to invoke {runtime}"
        report.observations.append(SandboxObservation(kind="runtime_error", detail=str(exc)))
        _finalize_probe_report(report)
        return report

    report.exit_code = completed.returncode
    report.stdout = completed.stdout
    report.stderr = completed.stderr
    report.install_succeeded = "INSTALL_OK" in completed.stdout
    report.import_succeeded = "IMPORT_OK" in completed.stdout
    report.observations.extend(_derive_observations(completed.stdout, completed.stderr, allow_network))
    _finalize_probe_report(report)
    return report


def exec_in_sandbox(
    root: Path,
    package: str,
    command: Sequence[str],
    *,
    force: bool = False,
    allow_network: bool = False,
    pull_image: bool = True,
    image: str = "python:3.11-slim",
    runtime: str = "docker",
    docker_options: SandboxDockerOptions | None = None,
) -> int:
    docker_options = docker_options or SandboxDockerOptions()
    executable = shutil.which(runtime)
    if executable is None:
        raise RuntimeError(f"{runtime} is not installed or not on PATH")

    risk = _find_package_risk(root, package)
    allowed_by_policy, policy_reason = _sandbox_policy(risk, package, force)
    if not allowed_by_policy:
        raise RuntimeError(policy_reason)

    docker_command = _docker_exec_command(
        executable=executable,
        package=package,
        image=image,
        allow_network=allow_network,
        pull_image=pull_image,
        command=list(command),
        docker_options=docker_options,
    )
    completed = subprocess.run(docker_command, cwd=root, check=False)
    return completed.returncode


def shell_in_sandbox(
    root: Path,
    package: str,
    *,
    force: bool = False,
    allow_network: bool = False,
    pull_image: bool = True,
    image: str = "python:3.11-slim",
    runtime: str = "docker",
    shell: str = "/bin/sh",
    docker_options: SandboxDockerOptions | None = None,
) -> int:
    docker_options = docker_options or SandboxDockerOptions()
    executable = shutil.which(runtime)
    if executable is None:
        raise RuntimeError(f"{runtime} is not installed or not on PATH")

    risk = _find_package_risk(root, package)
    allowed_by_policy, policy_reason = _sandbox_policy(risk, package, force)
    if not allowed_by_policy:
        raise RuntimeError(policy_reason)

    docker_command = _docker_shell_command(
        executable=executable,
        package=package,
        image=image,
        allow_network=allow_network,
        pull_image=pull_image,
        shell=shell,
        docker_options=docker_options,
    )
    completed = subprocess.run(docker_command, cwd=root, check=False)
    return completed.returncode


def _find_package_risk(root: Path, package: str) -> PackageRisk | None:
    result = scan_project(root)
    package_key = package.lower()
    for candidate in result.packages:
        if candidate.package.lower() == package_key:
            return candidate
    return None


def _sandbox_policy(risk: PackageRisk | None, package: str, force: bool) -> tuple[bool, str]:
    if force:
        return True, "sandbox forced by user override"
    if risk is None:
        return False, f"{package} is not present in the scanned project; use --force to sandbox an arbitrary package"
    if risk.risk_level in {"high", "critical"}:
        return True, f"{package} is eligible for sandboxing because its risk level is {risk.risk_level}"
    return False, f"{package} is risk level {risk.risk_level}; sandboxing is restricted to high/critical packages unless --force is used"


def _docker_probe_command(
    *,
    executable: str,
    package: str,
    import_name: str,
    image: str,
    allow_network: bool,
    pull_image: bool,
    docker_options: SandboxDockerOptions,
) -> list[str]:
    script = _container_script(package, import_name)
    command = _docker_base_command(
        executable=executable,
        image=image,
        allow_network=allow_network,
        pull_image=pull_image,
        docker_options=docker_options,
    )
    command.extend([image, "sh", "-lc", script])
    return command


def _docker_exec_command(
    *,
    executable: str,
    package: str,
    image: str,
    allow_network: bool,
    pull_image: bool,
    command: list[str],
    docker_options: SandboxDockerOptions,
) -> list[str]:
    if not command:
        raise ValueError("sandbox exec requires a command to run")
    container_script = _exec_script(package, command)
    docker_command = _docker_base_command(
        executable=executable,
        image=image,
        allow_network=allow_network,
        pull_image=pull_image,
        docker_options=docker_options,
    )
    docker_command.extend([image, "sh", "-lc", container_script])
    return docker_command


def _docker_shell_command(
    *,
    executable: str,
    package: str,
    image: str,
    allow_network: bool,
    pull_image: bool,
    shell: str,
    docker_options: SandboxDockerOptions,
) -> list[str]:
    docker_command = _docker_base_command(
        executable=executable,
        image=image,
        allow_network=allow_network,
        pull_image=pull_image,
        docker_options=docker_options,
        interactive=True,
    )
    docker_command.extend([image, "sh", "-lc", _shell_script(package, shell)])
    return docker_command


def _docker_base_command(
    *,
    executable: str,
    image: str,
    allow_network: bool,
    pull_image: bool,
    docker_options: SandboxDockerOptions,
    interactive: bool = False,
) -> list[str]:
    command = [
        executable,
        "run",
        "--rm",
        "--pull",
        "missing" if pull_image else "never",
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
        "--pids-limit",
        docker_options.pids_limit,
        "--memory",
        docker_options.memory,
        "--cpus",
        docker_options.cpus,
        "--read-only",
        "--user",
        docker_options.user,
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={docker_options.tmpfs_size}",
        "--tmpfs",
        f"/workspace:rw,noexec,nosuid,nodev,mode=1777,size={docker_options.tmpfs_size}",
        "--tmpfs",
        f"/venv:rw,exec,nosuid,nodev,size={docker_options.tmpfs_size}",
        "-w",
        "/workspace",
    ]
    if interactive:
        command.extend(["-it"])
    if not allow_network:
        command.extend(["--network", "none"])
    command.extend(docker_options.extra_args)
    return command


def _container_script(package: str, import_name: str) -> str:
    pip_target = shlex.quote(package)
    import_target = json.dumps(import_name)
    return (
        "set -eu\n"
        "python -m venv /venv/sg-venv\n"
        ". /venv/sg-venv/bin/activate\n"
        "python -m pip install --no-cache-dir --disable-pip-version-check pip setuptools wheel >/dev/null 2>&1\n"
        f"python -m pip install --no-cache-dir --disable-pip-version-check {pip_target}\n"
        "echo INSTALL_OK\n"
        f"python -c 'import importlib, json; importlib.import_module(json.loads({json.dumps(import_target)})); print(\"IMPORT_OK\")'\n"
    )


def _exec_script(package: str, command: list[str]) -> str:
    quoted_command = shlex.join(command)
    return (
        "set -eu\n"
        "python -m venv /venv/sg-venv\n"
        ". /venv/sg-venv/bin/activate\n"
        "python -m pip install --no-cache-dir --disable-pip-version-check pip setuptools wheel >/dev/null 2>&1\n"
        f"python -m pip install --no-cache-dir --disable-pip-version-check {shlex.quote(package)}\n"
        f"exec {quoted_command}\n"
    )


def _shell_script(package: str, shell: str) -> str:
    quoted_shell = shlex.quote(shell)
    return (
        "set -eu\n"
        "python -m venv /venv/sg-venv\n"
        ". /venv/sg-venv/bin/activate\n"
        "python -m pip install --no-cache-dir --disable-pip-version-check pip setuptools wheel >/dev/null 2>&1\n"
        f"python -m pip install --no-cache-dir --disable-pip-version-check {shlex.quote(package)}\n"
        f"exec {quoted_shell}\n"
    )


def _guess_import_name(package: str) -> str:
    base = re.split(r"[\[<>=!~ ]", package, maxsplit=1)[0]
    return base.replace("-", "_").lower()


def _derive_observations(stdout: str, stderr: str, allow_network: bool) -> list[SandboxObservation]:
    observations: list[SandboxObservation] = []
    install_succeeded = "INSTALL_OK" in stdout
    import_succeeded = "IMPORT_OK" in stdout
    if install_succeeded:
        observations.append(SandboxObservation(kind="install", detail="pip installed the package inside the sandbox"))
    else:
        observations.append(
            SandboxObservation(
                kind="install",
                detail="pip did not finish installing the package inside the sandbox; review stderr for the installer error",
            )
        )
    if import_succeeded:
        observations.append(SandboxObservation(kind="import", detail="the package imported successfully after installation"))
    elif install_succeeded:
        observations.append(
            SandboxObservation(
                kind="import",
                detail="installation finished, but the package failed during import; this often points to missing runtime support or native extension issues",
            )
        )
    else:
        observations.append(SandboxObservation(kind="import", detail="import check was not reached because installation failed"))
    if not allow_network:
        observations.append(
            SandboxObservation(
                kind="network_policy",
                detail="container networking was disabled; rerun with --allow-network if package installation needs network access",
            )
        )
    if "Temporary failure in name resolution" in stderr or "No matching distribution found" in stderr:
        observations.append(
            SandboxObservation(
                kind="network_or_index_failure",
                detail="package installation could not reach package indexes or resolve dependencies",
            )
        )
    if "No space left on device" in stderr:
        observations.append(
            SandboxObservation(
                kind="sandbox_storage",
                detail="the sandbox ran out of writable space; increase tmpfs size with a Docker argument or use a larger sandbox profile",
            )
        )
    if "failed to map segment from shared object" in stderr:
        observations.append(
            SandboxObservation(
                kind="native_extension_load_failure",
                detail=(
                    "a compiled package extension could not be loaded; this is usually caused by an executable "
                    "permission restriction on the virtualenv mount"
                ),
            )
        )
    if "permission denied while trying to connect to the Docker daemon socket" in stderr:
        observations.append(
            SandboxObservation(
                kind="docker_daemon_access",
                detail="the current user cannot access the Docker daemon socket",
            )
        )
    return observations


def _finalize_probe_report(report: SandboxReport) -> None:
    if not report.allowed_by_policy:
        report.status = "blocked_by_policy"
        report.summary = "Sandbox probe was blocked by policy before the container ran."
        report.recommended_action = "Use --force only if you intentionally want to probe a package outside the risk policy."
        return
    if report.exit_code is None:
        report.status = "not_run"
        report.summary = "Sandbox probe did not complete because the container runtime could not be invoked."
        report.recommended_action = "Check the container runtime installation and permissions."
        return
    if report.install_succeeded and report.import_succeeded:
        report.status = "passed"
        report.summary = "Package installed and imported successfully inside the sandbox."
        report.recommended_action = "Review observations and raw output if you need additional assurance."
        return
    if not report.install_succeeded:
        report.status = "install_failed"
        report.summary = "Package installation failed inside the sandbox."
        report.recommended_action = _installation_failure_action(report)
        return
    report.status = "import_failed"
    report.summary = "Package installed, but importing it failed inside the sandbox."
    report.recommended_action = _import_failure_action(report)


def _installation_failure_action(report: SandboxReport) -> str:
    stderr = report.stderr
    if not report.network_enabled and (
        "Temporary failure in name resolution" in stderr
        or "Could not find a version that satisfies the requirement" in stderr
        or "No matching distribution found" in stderr
    ):
        return "Rerun with --allow-network if you expect pip to download the package from an index."
    if "No space left on device" in stderr:
        return "Increase sandbox writable space, then rerun the probe."
    return "Review stderr for the pip error and rerun with adjusted sandbox or package settings."


def _import_failure_action(report: SandboxReport) -> str:
    stderr = report.stderr
    if "failed to map segment from shared object" in stderr:
        return "Rerun with the default executable /venv mount, or remove custom Docker args that make /venv noexec."
    if "No module named" in stderr:
        return "Check whether the import name differs from the package name and rerun with the correct package/import target when supported."
    return "Review stderr for the import traceback before trusting this package on the host."
