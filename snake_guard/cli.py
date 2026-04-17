from __future__ import annotations

import itertools
import os
import shutil
import sys
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import TypeVar

import typer

from snake_guard.installer import install_project
from snake_guard.remediation import build_fix_plan
from snake_guard.reporting import (
    as_pretty_json,
    render_fix_text,
    render_install_text,
    render_sandbox_text,
    render_scan_text,
)
from snake_guard.sandbox import (
    SandboxDockerOptions,
    exec_in_sandbox,
    probe_package,
    shell_in_sandbox,
)
from snake_guard.service import scan_project

app = typer.Typer(help="CLI dependency risk scanner for Python projects.")
sandbox_app = typer.Typer(help="Run risky packages inside a locked-down container.")
app.add_typer(sandbox_app, name="sandbox")
T = TypeVar("T")


def _resolve_root(root: Path) -> Path:
    return root.resolve()


@app.command(
    help="Install dependencies with a pre-scan and optional sandbox checks for risky packages.",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def install(
    ctx: typer.Context,
    root: Path = typer.Option(
        Path("."), "--root", help="Project directory to install."
    ),
    manager: str = typer.Option(
        "auto", "--manager", help="Installer backend: auto, pip, poetry, uv."
    ),
    requirement: Path | None = typer.Option(
        None, "--requirement", "-r", help="Requirements file for pip-style installs."
    ),
    package: list[str] = typer.Option(
        None,
        "--package",
        help="Package(s) to install directly, similar to pip install <pkg>.",
    ),
    sandbox_risky: bool = typer.Option(
        True,
        "--sandbox-risky/--skip-sandbox",
        help="Sandbox high/critical dependencies before running the real installer.",
    ),
    force_sandbox: bool = typer.Option(
        False,
        "--force-sandbox/--respect-sandbox-policy",
        help="Force sandbox runs even for packages that would otherwise be blocked by policy.",
    ),
    allow_network: bool = typer.Option(
        True,
        "--allow-network/--no-network",
        help="Allow or deny networking inside sandbox runs.",
    ),
    pull_image: bool = typer.Option(
        True,
        "--pull-image/--no-pull-image",
        help="Pull the sandbox image when it is missing locally.",
    ),
    continue_on_sandbox_failure: bool = typer.Option(
        False,
        "--continue-on-sandbox-failure/--block-on-sandbox-failure",
        help="Continue with install even if a sandbox run fails.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print the install plan, including which packages would be sandboxed, without executing sandbox or install commands.",
    ),
    sandbox_runtime: str = typer.Option(
        "docker", "--sandbox-runtime", help="Container runtime for sandboxing."
    ),
    sandbox_image: str = typer.Option(
        "python:3.11-slim", "--sandbox-image", help="Container image for sandboxing."
    ),
    docker_arg: list[str] = typer.Option(
        None,
        "--docker-arg",
        help="Additional Docker run argument for sandbox runs. Repeat for multiple arguments.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit JSON instead of text."
    ),
) -> None:
    installer_args = list(ctx.args)
    progress = _ProgressDisplay()
    try:
        report = _run_with_spinner(
            "Installing with guardrails",
            lambda: install_project(
                _resolve_root(root),
                manager=manager,
                requirement=requirement.resolve() if requirement is not None else None,
                packages=list(package or []),
                installer_args=installer_args,
                allow_network=allow_network,
                pull_image=pull_image,
                sandbox_runtime=sandbox_runtime,
                sandbox_image=sandbox_image,
                sandbox_docker_options=_sandbox_docker_options(docker_arg),
                force_sandbox=force_sandbox,
                sandbox_risky=sandbox_risky,
                continue_on_sandbox_failure=continue_on_sandbox_failure,
                dry_run=dry_run,
                progress_callback=progress.log,
            ),
            progress,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    if json_output:
        typer.echo(as_pretty_json(report.to_dict()))
        raise typer.Exit(code=_exit_code_for_install(report))
    typer.echo(render_install_text(report))
    raise typer.Exit(code=_exit_code_for_install(report))


@app.command(
    help="Scan project dependencies for vulnerabilities, malware signals, and provenance issues."
)
def scan(
    root: Path = typer.Option(Path("."), "--root", help="Project directory to scan."),
    verify_mode: bool = typer.Option(
        False,
        "--verify",
        help="Apply verify logic to the scan result and fail if high/critical or suspicious packages are present.",
    ),
    include_transitive: bool = typer.Option(
        False,
        "--include-transitive",
        help="Include transitive dependencies in the human-readable report. By default only direct dependencies are shown.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit JSON instead of text."
    ),
) -> None:
    progress = _ProgressDisplay()
    result = _run_with_spinner(
        "Scanning dependencies",
        lambda: scan_project(_resolve_root(root), progress_callback=progress.log),
        progress,
    )
    if verify_mode:
        suspicious = result.suspicious_packages()
        payload = {
            "verified": not suspicious
            and not any(
                package.risk_level in {"high", "critical"}
                for package in result.packages
            ),
            "suspicious_packages": [package.to_dict() for package in suspicious],
            "packages": [package.to_dict() for package in result.packages],
            "issues": [issue.to_dict() for issue in result.issues],
            "mode": "verify",
        }
        if json_output:
            typer.echo(as_pretty_json(payload))
            raise typer.Exit(code=0 if payload["verified"] else 1)
        typer.echo(as_pretty_json(payload))
        raise typer.Exit(code=0 if payload["verified"] else 1)
    if json_output:
        typer.echo(as_pretty_json(result.to_dict()))
        raise typer.Exit(code=_exit_code_for_scan(result))
    typer.echo(render_scan_text(result, include_transitive=include_transitive))
    raise typer.Exit(code=_exit_code_for_scan(result))


@app.command(
    help="Update vulnerable direct dependencies and refresh Poetry or uv lock files, or preview the exact diff with --plan."
)
def fix(
    root: Path = typer.Option(Path("."), "--root", help="Project directory to scan."),
    plan: bool = typer.Option(
        False, "--plan", help="Preview the fix plan without editing files."
    ),
    include_transitive: bool = typer.Option(
        False,
        "--include-transitive",
        help="Include transitive dependency upgrade suggestions in the human-readable fix report.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit JSON instead of text."
    ),
) -> None:
    resolved_root = _resolve_root(root)
    progress = _ProgressDisplay()
    started_at = time.perf_counter()
    try:
        result = _run_with_spinner(
            "Scanning dependencies",
            lambda: scan_project(resolved_root, progress_callback=progress.log),
            progress,
        )
        fix_plan, diff = _run_with_spinner(
            "Building remediation plan",
            lambda: build_fix_plan(
                resolved_root, result, apply=not plan, progress_callback=progress.log
            ),
        )
        payload = {
            "scan": result.to_dict(),
            "fix_plan": fix_plan.to_dict(),
            "diff": diff,
        }
        if json_output:
            typer.echo(as_pretty_json(payload))
            raise typer.Exit(code=_exit_code_for_fix(fix_plan, result.engine_statuses))
        typer.echo(
            render_fix_text(
                fix_plan,
                diff,
                include_transitive=include_transitive,
                engine_statuses=result.engine_statuses,
            )
        )
        raise typer.Exit(code=_exit_code_for_fix(fix_plan, result.engine_statuses))
    finally:
        _echo_elapsed_time(started_at)


@sandbox_app.command("probe")
def sandbox_probe(
    package: str = typer.Argument(
        ..., help="Package name or requirement specifier to sandbox."
    ),
    root: Path = typer.Option(
        Path("."), "--root", help="Project directory used for risk gating."
    ),
    force: bool = typer.Option(
        False,
        "--force/--respect-policy",
        help="Allow sandboxing even when the package is not high or critical risk.",
    ),
    allow_network: bool = typer.Option(
        False,
        "--allow-network/--no-network",
        help="Enable or disable container networking during install.",
    ),
    pull_image: bool = typer.Option(
        True,
        "--pull-image/--no-pull-image",
        help="Pull the container image when it is missing locally.",
    ),
    image: str = typer.Option(
        "python:3.11-slim", "--image", help="Container image to use."
    ),
    runtime: str = typer.Option(
        "docker", "--runtime", help="Container runtime executable."
    ),
    docker_arg: list[str] = typer.Option(
        None,
        "--docker-arg",
        help="Additional Docker run argument. Repeat for multiple arguments.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit JSON instead of text."
    ),
    save_report: Path | None = typer.Option(
        None, "--save-report", help="Optional path to write the JSON report."
    ),
) -> None:
    report_path = (
        _validate_output_file(save_report, "--save-report")
        if save_report is not None
        else None
    )
    progress = _ProgressDisplay()
    report = _run_with_spinner(
        f"Sandboxing {package}",
        lambda: probe_package(
            _resolve_root(root),
            package,
            force=force,
            allow_network=allow_network,
            pull_image=pull_image,
            image=image,
            runtime=runtime,
            docker_options=_sandbox_docker_options(docker_arg),
        ),
        progress,
    )
    if report_path is not None:
        _write_json_report(report_path, report.to_dict(), "--save-report")
    if json_output:
        typer.echo(as_pretty_json(report.to_dict()))
        raise typer.Exit(code=_exit_code_for_sandbox(report))
    typer.echo(render_sandbox_text(report))
    raise typer.Exit(code=_exit_code_for_sandbox(report))


@sandbox_app.command(
    "exec", context_settings={"allow_extra_args": True, "ignore_unknown_options": True}
)
def sandbox_exec(
    ctx: typer.Context,
    package: str = typer.Argument(
        ..., help="Package name or requirement specifier to sandbox."
    ),
    root: Path = typer.Option(
        Path("."), "--root", help="Project directory used for risk gating."
    ),
    force: bool = typer.Option(
        False,
        "--force/--respect-policy",
        help="Allow sandboxing even when the package is not high or critical risk.",
    ),
    allow_network: bool = typer.Option(
        False,
        "--allow-network/--no-network",
        help="Enable or disable container networking during install.",
    ),
    pull_image: bool = typer.Option(
        True,
        "--pull-image/--no-pull-image",
        help="Pull the container image when it is missing locally.",
    ),
    image: str = typer.Option(
        "python:3.11-slim", "--image", help="Container image to use."
    ),
    runtime: str = typer.Option(
        "docker", "--runtime", help="Container runtime executable."
    ),
    docker_arg: list[str] = typer.Option(
        None,
        "--docker-arg",
        help="Additional Docker run argument. Repeat for multiple arguments.",
    ),
) -> None:
    if not ctx.args:
        raise typer.BadParameter(
            "Provide a command after `--`, for example: snake-guard sandbox exec Django -- python -c 'import django'"
        )
    exit_code = exec_in_sandbox(
        _resolve_root(root),
        package,
        ctx.args,
        force=force,
        allow_network=allow_network,
        pull_image=pull_image,
        image=image,
        runtime=runtime,
        docker_options=_sandbox_docker_options(docker_arg),
    )
    raise typer.Exit(code=exit_code)


@sandbox_app.command("shell")
def sandbox_shell(
    package: str = typer.Argument(
        ..., help="Package name or requirement specifier to sandbox."
    ),
    root: Path = typer.Option(
        Path("."), "--root", help="Project directory used for risk gating."
    ),
    force: bool = typer.Option(
        False,
        "--force/--respect-policy",
        help="Allow sandboxing even when the package is not high or critical risk.",
    ),
    allow_network: bool = typer.Option(
        False,
        "--allow-network/--no-network",
        help="Enable or disable container networking during install.",
    ),
    pull_image: bool = typer.Option(
        True,
        "--pull-image/--no-pull-image",
        help="Pull the container image when it is missing locally.",
    ),
    image: str = typer.Option(
        "python:3.11-slim", "--image", help="Container image to use."
    ),
    runtime: str = typer.Option(
        "docker", "--runtime", help="Container runtime executable."
    ),
    shell: str = typer.Option(
        "/bin/sh", "--shell", help="Shell binary to launch inside the sandbox."
    ),
    docker_arg: list[str] = typer.Option(
        None,
        "--docker-arg",
        help="Additional Docker run argument. Repeat for multiple arguments.",
    ),
) -> None:
    exit_code = shell_in_sandbox(
        _resolve_root(root),
        package,
        force=force,
        allow_network=allow_network,
        pull_image=pull_image,
        image=image,
        runtime=runtime,
        shell=shell,
        docker_options=_sandbox_docker_options(docker_arg),
    )
    raise typer.Exit(code=exit_code)


def _exit_code_for_scan(result) -> int:
    if any(package.risk_level == "critical" for package in result.packages):
        return 2
    if any(package.risk_level == "high" for package in result.packages):
        return 1
    return 0


def _exit_code_for_fix(plan, engine_statuses=None) -> int:
    if any(action.action == "manual_review" for action in plan.actions):
        return 2
    if any(action.action == "upgrade" for action in plan.actions):
        return 1
    if any(status.status != "passed" for status in engine_statuses or []):
        return 1
    return 0


def _exit_code_for_sandbox(report) -> int:
    if not report.allowed_by_policy:
        return 2
    if report.exit_code not in {0, None}:
        return 1
    if not report.install_succeeded or not report.import_succeeded:
        return 1
    return 0


def _exit_code_for_install(report) -> int:
    return 0 if report.succeeded() else 1


def _run_with_spinner(
    message: str, action: Callable[[], T], progress: "_ProgressDisplay | None" = None
) -> T:
    with _spinner(message, progress):
        return action()


def _sandbox_docker_options(docker_args: list[str] | None) -> SandboxDockerOptions:
    return SandboxDockerOptions(extra_args=list(docker_args or []))


def _validate_output_file(path: Path, option_name: str) -> Path:
    expanded_path = path.expanduser()
    if expanded_path.exists() and expanded_path.is_dir():
        raise typer.BadParameter(
            f"{option_name} must be a file path, not a directory: {expanded_path}"
        )

    parent = expanded_path.parent if expanded_path.parent != Path("") else Path(".")
    if not parent.exists():
        raise typer.BadParameter(
            f"{option_name} parent directory does not exist: {parent}"
        )
    if not parent.is_dir():
        raise typer.BadParameter(
            f"{option_name} parent path is not a directory: {parent}"
        )
    if not os.access(parent, os.W_OK):
        raise typer.BadParameter(
            f"{option_name} parent directory is not writable: {parent}"
        )
    if expanded_path.exists() and not os.access(expanded_path, os.W_OK):
        raise typer.BadParameter(f"{option_name} file is not writable: {expanded_path}")
    return expanded_path


def _write_json_report(path: Path, payload: dict, option_name: str) -> None:
    try:
        path.write_text(as_pretty_json(payload), encoding="utf-8")
    except OSError as exc:
        raise typer.BadParameter(
            f"failed to write {option_name} file {path}: {exc}"
        ) from exc


@contextmanager
def _spinner(message: str, progress: "_ProgressDisplay | None" = None):
    stop_event = threading.Event()

    def spin() -> None:
        for frame in itertools.cycle("|/-\\"):
            if stop_event.is_set():
                break
            status = progress.status_text() if progress is not None else ""
            sys.stderr.write("\r" + _spinner_line(frame, message, status))
            sys.stderr.flush()
            time.sleep(0.1)
        sys.stderr.write("\r" + " " * _terminal_width())
        sys.stderr.write("\r")
        sys.stderr.flush()

    thread = threading.Thread(target=spin, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop_event.set()
        thread.join()


class _ProgressDisplay:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._status = ""
        self._completed_scan_engines: set[str] = set()

    def log(self, message: str) -> None:
        with self._lock:
            summary = self._summarize(message)
            if not summary:
                return
            self._status = summary

    def status_text(self) -> str:
        with self._lock:
            return self._status

    def _summarize(self, message: str) -> str:
        if message.startswith(("inventory: found ", "inventory: prepared ")):
            self._completed_scan_engines.clear()
        scan_summary = self._summarize_scan_engine(message)
        if scan_summary:
            return scan_summary
        return _summarize_progress(message)

    def _summarize_scan_engine(self, message: str) -> str:
        scan_labels = {
            "pip-audit": "advisories",
            "guarddog": "malware heuristics",
            "provenance": "provenance",
        }
        for engine_name, label in scan_labels.items():
            if message == f"{engine_name}: completed":
                self._completed_scan_engines.add(engine_name)
                remaining = [
                    name
                    for name in scan_labels
                    if name not in self._completed_scan_engines
                ]
                if remaining:
                    remaining_labels = ", ".join(
                        scan_labels[name] for name in remaining
                    )
                    return f"loading remaining checks: {remaining_labels}"
                return "completing scan"
            if message == f"{engine_name}: started":
                remaining = [
                    name
                    for name in scan_labels
                    if name != engine_name and name not in self._completed_scan_engines
                ]
                if remaining:
                    remaining_labels = ", ".join(
                        scan_labels[name] for name in remaining
                    )
                    return f"running {label}; waiting on {remaining_labels}"
                return f"running {label}"
        return ""


def _summarize_progress(message: str) -> str:
    if message.startswith("fix: "):
        return message.removeprefix("fix: ")
    if message.startswith("inventory: found "):
        direct_count = message.split("inventory: found ", 1)[1].split(" direct", 1)[0]
        return f"found {direct_count} direct dependencies"
    if message.startswith("inventory: prepared "):
        direct_count = message.split("inventory: prepared ", 1)[1].split(" direct", 1)[
            0
        ]
        return f"prepared {direct_count} direct dependencies"
    if message.startswith("install: detecting manager"):
        return "detecting installer"
    if message.startswith("install: loading dependency scan"):
        return "loading dependency scan"
    if message.startswith("install: loading dry-run plan"):
        return "loading install plan"
    if message.startswith("install: loading sandbox checks"):
        return "loading sandbox checks"
    if message.startswith("install: sandboxing "):
        return message.removeprefix("install: ")
    if message.startswith("install: loading dependency installer"):
        return "loading dependency installer"
    if message.startswith("install: running dependency installer"):
        return "running dependency installer"
    if message.startswith("install: loading verification scan"):
        return "loading verification scan"
    if message.startswith("pip-audit:"):
        if "completed" in message:
            return "loading remaining checks"
        return "checking vulnerability advisories"
    if message.startswith("guarddog: scanning "):
        package = message.removeprefix("guarddog: scanning ")
        return f"scanning {package}"
    if message.startswith("guarddog: finished "):
        package = message.removeprefix("guarddog: finished ")
        return f"checked {package}"
    if message == "guarddog: verifying generated dependency set":
        return "verifying generated dependency set"
    if message == "guarddog: verifying requirements.txt":
        return "verifying requirements.txt"
    if message.startswith("guarddog:"):
        if "completed" in message:
            return "loading remaining checks"
        return "running malware heuristics"
    if message.startswith("provenance: checking "):
        package = message.removeprefix("provenance: checking ")
        return f"checking {package}"
    if message.startswith("provenance: finished "):
        package = message.removeprefix("provenance: finished ")
        return f"checked {package}"
    if message.startswith("provenance:"):
        if "completed" in message:
            return "completing scan"
        if "finished" in message:
            return "loading remaining provenance checks"
        return "checking package provenance"
    return ""


def _echo_elapsed_time(started_at: float) -> None:
    elapsed = time.perf_counter() - started_at
    sys.stderr.write(f"{_green_arrow()} Completed in {_format_elapsed(elapsed)}\n")
    sys.stderr.flush()


def _format_elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, remainder = divmod(seconds, 60)
    hours, minutes = divmod(int(minutes), 60)
    if hours:
        return f"{hours}h {minutes}m {remainder:.2f}s"
    return f"{minutes}m {remainder:.2f}s"


def _green_arrow() -> str:
    arrow = "➜"
    if sys.stderr.isatty():
        return f"\033[32m{arrow}\033[0m"
    return arrow


def _spinner_line(frame: str, message: str, status: str) -> str:
    base = f"{frame} {message}"
    if status:
        base += f" [{status}]"
    base += "..."
    return _truncate_to_width(base, _terminal_width())


def _terminal_width() -> int:
    return max(shutil.get_terminal_size(fallback=(80, 20)).columns, 20)


def _truncate_to_width(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."
