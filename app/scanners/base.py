"""
Purpose: Abstract base class interface for security scanners.

Responsibilities:
- Enforce common interface contract across all scanner implementations.

Dependencies:
- abc.ABC, abstractmethod
- pathlib.Path
- typing.List, Dict, Any

Usage:
    class MyScanner(BaseScanner):
        async def scan(self, target_dir: Path) -> List[Dict[str, Any]]:
            ...
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List


class BaseScanner(ABC):
    """Abstract interface contract for security analysis scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the scanner engine."""
        pass

    @abstractmethod
    async def scan(self, target_dir: Path) -> List[Dict[str, Any]]:
        """Run security scan on target directory and return findings."""
        pass
