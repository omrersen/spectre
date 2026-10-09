"""Plugin system for Spectre scanners."""
from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from pathlib import Path

from spectre.models import Finding


class PluginBase(ABC):
    """Base class for all Spectre plugins."""

    name: str = "unnamed"
    description: str = ""
    version: str = "0.1.0"
    author: str = ""

    @abstractmethod
    async def scan(self, target: str) -> list[Finding]:
        """Run the plugin scan against a target."""
        ...


_registry: dict[str, type[PluginBase]] = {}


def register(cls: type[PluginBase]) -> type[PluginBase]:
    """Class decorator to register a plugin."""
    _registry[cls.name] = cls
    return cls


def get_plugin(name: str) -> type[PluginBase] | None:
    return _registry.get(name)


def list_plugins() -> list[str]:
    return sorted(_registry.keys())


def load_plugins_from_dir(directory: str | Path) -> int:
    """Dynamically load plugin modules from a directory."""
    directory = Path(directory)
    count = 0
    if not directory.is_dir():
        return 0

    import sys

    if str(directory.parent) not in sys.path:
        sys.path.insert(0, str(directory.parent))

    for module_info in pkgutil.iter_modules([str(directory)]):
        try:
            importlib.import_module(module_info.name)
            count += 1
        except Exception:
            continue

    return count


def load_entry_point_plugins() -> int:
    """Load plugins registered via entry points (spectre.plugins group)."""
    from importlib.metadata import entry_points

    count = 0
    try:
        eps = entry_points(group="spectre.plugins")
    except Exception:
        return 0

    for ep in eps:
        try:
            cls = ep.load()
            if issubclass(cls, PluginBase):
                register(cls)
                count += 1
        except Exception:
            continue

    return count
