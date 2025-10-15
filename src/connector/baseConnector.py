from abc import ABC, abstractmethod
from pathlib import Path

from src.utils.models import LLMAnswer


class Connector(ABC):
    @abstractmethod
    def connect(self, logPath: Path, hardened: bool) -> tuple[list[LLMAnswer], float]:
        pass