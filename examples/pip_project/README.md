# pip Example Project

This project is a small pip-style target for testing `snake-guard`.

It includes:

- `requirements.txt`: pip dependency declarations with pinned and unpinned packages
- `reinstall.sh`: optional helper that reinstalls the local `snake-guard` package from the repo root

## Scan

From the repository root:

```bash
snake-guard scan --root examples/pip_project
snake-guard scan --root examples/pip_project --include-transitive
```

## Install Wrapper

Run:

```bash
snake-guard install --root examples/pip_project --dry-run
snake-guard install --root examples/pip_project
```

## Local Reinstall Helper

From the repository root:

```bash
cd examples/pip_project
chmod +x reinstall.sh
./reinstall.sh
```

