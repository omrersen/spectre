from abc import ABC, abstractmethod

from spectre.models import Finding


class BaseScanner(ABC):
    """Base class for all scanners."""
    
    name: str = "base"
    description: str = ""
    version: str = "1.0.0"
    
    @abstractmethod
    async def scan(self, target: str) -> list[Finding]:
        """Scan a target and return findings."""
        pass
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}({self.name})>"
