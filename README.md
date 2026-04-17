# snake-guard

`snake-guard` is a CLI dependency risk scanner for Python projects. It helps
developers detect vulnerable, suspicious, or risky packages before they become
part of a project or CI pipeline.

It aggregates known vulnerability scanners and package-risk checks, then unifies
their results into one easy-to-use command-line interface. It builds an inventory
from common Python manifests and reports vulnerabilities, suspicious package
signals, provenance issues, and safe remediation guidance in one place.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Fix Plans](#fix-plans)
  - [Install Wrapper](#install-wrapper)
  - [Sandbox](#sandbox)
  - [JSON Output](#json-output)
  - [Scheduled CI Scans](#scheduled-ci-scans)
- [Supported Package Managers](#supported-package-managers)
- [Built With](#built-with)
- [Contributing](#contributing)
- [License](#license)

## Features

- Full project scans for known vulnerabilities using multiple scanners and
  package-risk checks.
- Isolated package sandboxing to probe, import, or run commands before trusting a
  dependency in your local environment.
- Automatic dependency fix plans for vulnerable direct dependencies, with
  conservative project edits where safe.
- Safer install wrapper that scans before installation, sandboxes risky packages,
  and verifies the project after install.
- Per-engine pass or fail status so missing tools, scanner errors, and findings
  are visible instead of hidden behind a clean-looking result.

## Installation

Install `snake-guard` from PyPI:

```bash
pip install snake-guard
```

For local development, install this repository in editable mode:

```bash
python -m pip install -e .
```

Sandbox commands use a container runtime. Docker is the default runtime:

```bash
docker --version
```

Other Docker-compatible runtimes may work when passed with `--runtime`, but the
sandbox command arguments are Docker-style today.

## Usage

Scan the current project:

```bash
snake-guard scan
```

Emit JSON for scripts or CI:

```bash
snake-guard scan --json
```

Use verify mode as a policy gate. It exits non-zero when high-risk findings are
present:

```bash
snake-guard scan --verify
```

Preview remediation without editing files:

```bash
snake-guard fix --plan
```

Apply available fixes:

```bash
snake-guard fix
```

Run against an example project:

```bash
snake-guard scan --root examples/pip_project
snake-guard scan --root examples/poetry_project
snake-guard scan --root examples/uv_project
```

## Fix Plans

`snake-guard fix` separates real fixes from recommendations:

- Fix actions are generated for vulnerable packages when a safe target version is
  known.
- Pinning recommendations are shown for direct dependencies that use ranges or
  compatible-release specifiers.
- Engine status is shown next to the plan, so a clean plan does not hide a failed
  scanner.

Example:

```bash
snake-guard fix --plan
```

If no actions are required and every engine passed, the output says the project is
good to go. If no actions are generated but an engine failed, the output makes
that explicit so the result is not treated as clean.

## Install Wrapper

The installation wrapper runs a pre-scan, optionally sandboxes risky packages, and then
delegates to the real installer.

```bash
snake-guard install --root examples/pip_project
snake-guard install -r requirements.txt
snake-guard install --dry-run
snake-guard install --manager poetry -- --with dev
snake-guard install --manager uv -- --frozen
snake-guard install --package requests --package flask
```

Use `--dry-run` to see what would happen without running sandbox checks or the
underlying installer.

## Sandbox

Sandbox mode is useful when you want to inspect a package before installing it in
your real environment. By default, direct sandbox commands disable networking
inside the container.

```bash
snake-guard sandbox probe Django --force
snake-guard sandbox exec Django --force -- python -c "import django; print(django.get_version())"
snake-guard sandbox shell Django --force
```

Available sandbox modes:

- `probe`: install a package and attempt a basic import in an isolated container.
- `exec`: install a package and run a command inside the sandbox.
- `shell`: install a package and open an interactive shell inside the sandbox.

Useful sandbox options:

- `--allow-network` enables container networking during package installation.
- `--no-pull-image` requires the sandbox image to already exist locally.
- `--image` changes the Python container image.
- `--runtime` changes the container runtime executable.
- `--docker-arg` passes extra Docker-style arguments to the sandbox run.

## JSON Output

Most commands support `--json` for automation:

```bash
snake-guard scan --json
snake-guard fix --plan --json
snake-guard sandbox probe requests --force --json
```

The JSON report includes the dependency inventory, package findings, engine
statuses, fix actions, and recommendations where applicable.

## Scheduled CI Scans

Dependency risk changes over time. A package that looked clean during install can
receive a new advisory or suspicious signal later. You can run `snake-guard` on a
schedule in CI to keep checking the project.

This repository includes a reusable GitHub Actions example at
`.github/workflows/snake-guard.yml`:


## Supported Package Managers

`snake-guard` currently reads these dependency sources:

- `requirements.txt`
- `pyproject.toml`
- `poetry.lock`
- `uv.lock`

The installation wrapper can detect or run these package managers:

- `pip`
- `poetry`
- `uv`

`snake-guard fix` can update vulnerable direct dependencies in `requirements.txt` or
`pyproject.toml` when a safe replacement is known. For Poetry and uv projects,
it rewrites the direct dependency specifier first, then runs `poetry lock` or
`uv lock` so the checked-in lock file matches the manifest. Use
`snake-guard fix --plan` to preview the manifest diff and the lock refresh
command before editing files.

## Built With

The core CLI is written in Python and uses:

- `Typer` for the command-line interface.
- `packaging` for version and requirement handling.
- `tomli` on older Python versions for TOML parsing.

Under the hood, scans use these engines:

- `pip-audit` for Python vulnerability advisories.
- `guarddog` for PyPI malware and suspicious-package heuristics.
- Built-in provenance checks against PyPI JSON and Integrity APIs.

`pip-audit` and `guarddog` are installed with `snake-guard`.

## Contributing

Contributions are welcome, especially around parser coverage, remediation safety,
test fixtures, and clearer reporting. Keep changes focused and include an example
or test fixture when behavior changes.

Before opening a change, run at least:

```bash
python -m compileall -q snake_guard
```

If your change depends on scan engines, also test real `pip-audit` and `guarddog`
runs so engine status and failure handling stay accurate.

## License

This project is licensed under the Apache License 2.0. See `LICENSE` for the
full license text.
