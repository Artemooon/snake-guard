from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from snake_guard.models import Dependency


class ManifestParser(ABC):
    filename: str

    @abstractmethod
    def parse(self, path: Path) -> list[Dependency]:
        raise NotImplementedError

