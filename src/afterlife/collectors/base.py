from abc import ABC, abstractmethod
from pathlib import Path


class Collector(ABC):
    """Pulls identities and credentials from one source system into the local DB."""

    source: str

    def __init__(self, db_path: Path):
        self.db_path = db_path

    @abstractmethod
    def run(self) -> int:
        """Collect records and return the count inserted/updated."""
