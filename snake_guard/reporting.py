from __future__ import annotations

import json

from packaging.version import InvalidVersion, Version
import typer

from snake_guard.models import EngineStatus, Finding, FindingType, FixPlan, InstallReport, PackageRisk, SandboxReport, ScanResult


def render_scan_text(result: ScanResult, include_transitive: bool = False) -> str:
    lines: list[str] = []
    lines.append(_heading("Inventory"))
    lines.append(f"  manifests: {', '.join(result.inventory.manifests) or 'none found'}")
    lines.append(f"  direct dependencies: {_good(str(len(result.inventory.direct_dependencies())))}")
    lines.append(f"  resolved dependencies: {_muted(str(len(result.inventory.resolved_dependencies())))}")

    if result.inventory.warnings:
        lines.append(_heading("Warnings"))
        for warning in result.inventory.warnings:
            lines.append(f"  - {_warn(warning)}")

    if result.engine_statuses:
        lines.append(_heading("Engine status"))
        lines.extend(_engine_status_line(status) for status in result.engine_statuses)

    visible_packages = result.packages if include_transitive else [package for package in result.packages if package.direct]
    hidden_transitive = len(result.packages) - len(visible_packages)

    lines.append(_heading("Packages"))
    if not visible_packages:
        lines.append(f"  {_good('no packages to report')}")
    for package in visible_packages:
        target_version = _target_version(package)
        summary = f"  - {_package_name(package.package)} [{_risk_label(package.risk_level)}]"
        if package.installed_version:
            summary += f" version={_version(package.installed_version)}"
        lines.append(summary)
        if target_version:
            lines.append(f"      recommended: {_good('upgrade')} to {_version(target_version)}")
            lines.append(f"      why: {_upgrade_reason(package)}")
        elif package.recommended_action == "manual_review":
            lines.append(f"      recommended: {_warn('manual review')}")

        vulnerability_ids = _vulnerability_ids(package.findings)
        if vulnerability_ids:
            lines.append(f"      vulnerabilities: {_bad(', '.join(vulnerability_ids))}")

        other_findings = _other_findings(package.findings)
        for finding in other_findings:
            detail = finding.identifier or finding.rule or finding.detail or "no detail"
            lines.append(f"      finding: {_warn(f'{finding.source}:{finding.type}')} {detail}")

    if hidden_transitive > 0:
        noun = "package is" if hidden_transitive == 1 else "packages are"
        lines.append(f"  {_muted(f'{hidden_transitive} transitive {noun} hidden by default; use --include-transitive to show them')}")

    if result.issues:
        lines.append(_heading("Engine issues"))
        for issue in result.issues:
            lines.append(f"  - {_warn(issue.engine)}: {issue.message}")
    return "\n".join(lines)


def render_fix_text(
    plan: FixPlan,
    diff: str | None,
    include_transitive: bool = False,
    engine_statuses: list[EngineStatus] | None = None,
) -> str:
    lines: list[str] = [_heading("Fix plan")]
    visible_actions = plan.actions if include_transitive else [action for action in plan.actions if action.direct]
    visible_recommendations = (
        plan.recommendations
        if include_transitive
        else [recommendation for recommendation in plan.recommendations if recommendation.direct]
    )
    failed_engines = [status for status in engine_statuses or [] if status.status != "passed"]
    hidden_transitive = len(plan.actions) - len(visible_actions)
    visible_packages = {action.package for action in visible_actions}

    if not visible_actions:
        if failed_engines:
            lines.append(
                f"  {_warn('No automatic or manual actions were generated, but one or more scan engines failed or reported findings')}"
            )
        else:
            message = "No automatic or manual actions were required. You are good to go"
            if visible_recommendations:
                message += ", but there are recommendations to use pinned dependency versions"
            lines.append(f"  {_good(message)}")
    elif visible_recommendations and not failed_engines:
        message = "There are recommendations to use pinned dependency versions"
        lines.append(f"  {_good(message)}")
    for action in visible_actions:
        action_label = _good(action.action) if action.action == "upgrade" else _warn(action.action)
        summary = f"  - {_package_name(action.package)}: {action_label}"
        if action.target_version:
            summary += f" -> {_version(action.target_version)}"
        if action.applied:
            summary += f" ({_good('applied')})"
        lines.append(summary)
        if action.detail:
            lines.append(f"      {action.detail}")
    if hidden_transitive > 0:
        noun = "package is" if hidden_transitive == 1 else "packages are"
        lines.append(f"  {_muted(f'{hidden_transitive} transitive {noun} hidden by default; use --include-transitive to show them')}")

    if engine_statuses:
        lines.append(_heading("Engine status"))
        lines.extend(_engine_status_line(status) for status in engine_statuses)

    if visible_recommendations:
        lines.append(_heading("Recommendations"))
        for recommendation in visible_recommendations:
            summary = f"  - {_package_name(recommendation.package)}: {recommendation.recommendation}"
            if recommendation.current_specifier:
                summary += f" Current specifier: {_version(recommendation.current_specifier)}."
            if recommendation.recommended_specifier:
                summary += f" Recommended specifier: {_version(recommendation.recommended_specifier)}."
            if recommendation.manifest:
                summary += f" Manifest: {recommendation.manifest}."
            lines.append(summary)

    visible_warnings = _filter_fix_warnings(plan.warnings, visible_packages, include_transitive)
    if visible_warnings:
        lines.append(_heading("Warnings"))
        for warning in visible_warnings:
            lines.append(f"  - {_warn(warning)}")
    if diff:
        lines.append(_heading("Diff"))
        lines.extend(_style_diff_line(line) for line in diff.rstrip().splitlines())
    return "\n".join(lines)


def _engine_status_line(status: EngineStatus) -> str:
    label = _good("passed") if status.status == "passed" else _bad("failed")
    detail = f": {status.message}" if status.message else ""
    return f"  - {_package_name(status.engine)}: {label}{detail}"


def render_sandbox_text(report: SandboxReport) -> str:
    lines: list[str] = [_heading("Sandbox report")]
    lines.append(f"  package: {_package_name(report.package)}")
    lines.append(f"  import name: {report.import_name}")
    lines.append(f"  runtime: {report.container_runtime}")
    lines.append(f"  image: {report.image}")
    policy = _good("allowed") if report.allowed_by_policy else _bad("blocked")
    lines.append(f"  policy: {policy}")
    lines.append(f"  reason: {report.policy_reason}")
    if report.summary:
        status = _good(report.status) if report.status == "passed" else _warn(report.status)
        lines.append(f"  result: {status} - {report.summary}")
    if report.recommended_action:
        lines.append(f"  recommended: {report.recommended_action}")
    if report.exit_code is not None:
        lines.append(f"  exit code: {report.exit_code}")
    lines.append(f"  install succeeded: {_bool_status(report.install_succeeded)}")
    lines.append(f"  import succeeded: {_bool_status(report.import_succeeded)}")
    if report.observations:
        lines.append(_heading("Observations"))
        for observation in report.observations:
            lines.append(f"  - {observation.kind}: {observation.detail}")
    if report.stdout.strip():
        lines.append(_heading("Stdout"))
        lines.extend(f"  {line}" for line in report.stdout.rstrip().splitlines())
    if report.stderr.strip():
        lines.append(_heading("Stderr"))
        lines.extend(f"  {line}" for line in report.stderr.rstrip().splitlines())
    return "\n".join(lines)


def render_install_text(report: InstallReport) -> str:
    lines: list[str] = [_heading("Install report")]
    lines.append(f"  root: {report.root}")
    lines.append(f"  manager: {report.manager}")
    lines.append(f"  mode: {_warn('dry-run') if report.dry_run else _good('execute')}")
    lines.append(f"  command: {' '.join(report.command)}")
    if report.planned_sandbox_packages:
        lines.append(_heading("Will sandbox before install"))
        for item in report.planned_sandbox_packages:
            lines.append(f"  - {_package_name(item.package)} [{_risk_label(item.risk_level or 'info')}]: {item.reason}")
    if report.planned_direct_install_packages:
        lines.append(_heading("Will install directly"))
        for item in report.planned_direct_install_packages:
            risk = f" [{_risk_label(item.risk_level)}]" if item.risk_level else ""
            lines.append(f"  - {_package_name(item.package)}{risk}: {item.reason}")
    lines.append(_heading("Stages"))
    for stage in report.stages:
        status = _good("ok") if stage.ok else _bad("failed")
        line = f"  - {stage.stage}: {status} - {stage.detail}"
        if stage.exit_code is not None:
            line += f" (exit={stage.exit_code})"
        lines.append(line)
    if report.sandbox_reports:
        lines.append(_heading("Sandboxed packages"))
        for sandbox_report in report.sandbox_reports:
            lines.append(
                f"  - {_package_name(sandbox_report.package)}: allowed={_bool_status(sandbox_report.allowed_by_policy)} "
                f"install={_bool_status(sandbox_report.install_succeeded)} import={_bool_status(sandbox_report.import_succeeded)}"
            )
    if report.install_stdout.strip():
        lines.append(_heading("Installer stdout"))
        lines.extend(f"  {line}" for line in report.install_stdout.rstrip().splitlines())
    if report.install_stderr.strip():
        lines.append(_heading("Installer stderr"))
        lines.extend(f"  {line}" for line in report.install_stderr.rstrip().splitlines())
    return "\n".join(lines)


def as_pretty_json(payload: dict) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def _target_version(package: PackageRisk) -> str | None:
    fix_versions: set[str] = set()
    for finding in package.findings:
        if finding.type == FindingType.KNOWN_VULN:
            fix_versions.update(version for version in finding.fixed_versions if version)
    return sorted(fix_versions, key=_version_sort_key)[-1] if fix_versions else None


def _version_sort_key(version: str) -> tuple[int, Version | str]:
    try:
        return 0, Version(version)
    except InvalidVersion:
        return 1, version


def _upgrade_reason(package: PackageRisk) -> str:
    vuln_count = len(_vulnerability_ids(package.findings))
    if vuln_count == 0:
        return "Known issues were detected in the installed version."
    suffix = "vulnerability" if vuln_count == 1 else "vulnerabilities"
    return f"The installed version is affected by {vuln_count} known {suffix}."


def _vulnerability_ids(findings: list[Finding]) -> list[str]:
    identifiers: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        if finding.type != FindingType.KNOWN_VULN:
            continue
        identifier = finding.identifier or finding.detail
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        identifiers.append(identifier)
    return identifiers


def _other_findings(findings: list[Finding]) -> list[Finding]:
    return [finding for finding in findings if finding.type != FindingType.KNOWN_VULN]


def _filter_fix_warnings(warnings: list[str], visible_packages: set[str], include_transitive: bool) -> list[str]:
    if include_transitive:
        return warnings

    filtered: list[str] = []
    for warning in warnings:
        package, separator, _ = warning.partition(":")
        if not separator:
            filtered.append(warning)
            continue
        if package in visible_packages:
            filtered.append(warning)
    return filtered


def _heading(text: str) -> str:
    return typer.style(text, bold=True, fg=typer.colors.BRIGHT_WHITE)


def _package_name(text: str) -> str:
    return typer.style(text, bold=True, fg=typer.colors.BRIGHT_BLUE)


def _version(text: str) -> str:
    return typer.style(text, fg=typer.colors.CYAN)


def _good(text: str) -> str:
    return typer.style(text, bold=True, fg=typer.colors.GREEN)


def _warn(text: str) -> str:
    return typer.style(text, bold=True, fg=typer.colors.YELLOW)


def _bad(text: str) -> str:
    return typer.style(text, bold=True, fg=typer.colors.RED)


def _muted(text: str) -> str:
    return typer.style(text, fg=typer.colors.BRIGHT_BLACK)


def _bool_status(value: bool) -> str:
    return _good("yes") if value else _bad("no")


def _risk_label(risk_level: str) -> str:
    palette = {
        "critical": _bad,
        "high": _bad,
        "medium": _warn,
        "low": _warn,
        "info": _good,
    }
    return palette.get(risk_level, _muted)(risk_level)


def _style_diff_line(line: str) -> str:
    if line.startswith("+++ ") or line.startswith("--- "):
        return _heading(line)
    if line.startswith("+"):
        return _good(line)
    if line.startswith("-"):
        return _bad(line)
    if line.startswith("@@"):
        return _warn(line)
    return line
