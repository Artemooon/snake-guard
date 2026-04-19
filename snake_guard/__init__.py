from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _package_version

__all__ = ["__version__"]

try:
    __version__ = _package_version("snake-guard")
except PackageNotFoundError:
    __version__ = "0.1.0"
