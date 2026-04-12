# uv Example Project

This project is a small uv-style target for testing `snake-guard`.

It includes:

- `pyproject.toml`: PEP 621 dependency declarations and a dev dependency group
- `uv.lock`: minimal lock data that `snake-guard` can parse as resolved dependencies

## Scan

From the repository root:

```bash
snake-guard scan --root examples/uv_project
snake-guard scan --root examples/uv_project --include-transitive
```

## Install Wrapper

If uv is installed, run:

```bash
snake-guard install --root examples/uv_project --manager uv --dry-run
snake-guard install --root examples/uv_project --manager uv -- --frozen
```

