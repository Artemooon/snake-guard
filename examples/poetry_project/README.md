# Poetry Example Project

This project is a small Poetry-style target for testing `snake-guard`.

It includes:

- `pyproject.toml`: Poetry dependency declarations
- `poetry.lock`: minimal lock data that `snake-guard` can parse as resolved dependencies

## Scan

From the repository root:

```bash
snake-guard scan --root examples/poetry_project
snake-guard scan --root examples/poetry_project --include-transitive
```

## Install Wrapper

If Poetry is installed, run:

```bash
snake-guard install --root examples/poetry_project --manager poetry --dry-run
snake-guard install --root examples/poetry_project --manager poetry
```

