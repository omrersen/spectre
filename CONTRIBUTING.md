# Contributing to Spectre

Thanks for your interest in contributing! 🎉

## Development Setup

```bash
git clone https://github.com/omrersen/spectre.git
cd spectre
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
pytest --cov=spectre
```

## Code Style

We use [ruff](https://github.com/astral-sh/ruff) for linting and formatting:

```bash
ruff check spectre/
ruff format spectre/
```

## Type Checking

```bash
mypy spectre/
```

## Adding a Scanner

1. Create a new file in `spectre/scanners/`
2. Inherit from `BaseScanner`
3. Implement the `scan` method
4. Register it in `spectre/cli.py`

```python
from .base import BaseScanner
from ..models import Finding, Severity

class MyScanner(BaseScanner):
    name = "my-scanner"
    description = "My custom scanner"
    
    async def scan(self, target: str) -> list[Finding]:
        return []
```

## Adding a Plugin

```python
from spectre.plugins import PluginBase, register

@register
class MyPlugin(PluginBase):
    name = "my-plugin"
    
    async def scan(self, target: str) -> list[Finding]:
        return []
```

## Pull Request Guidelines

- Fork the repo and create a feature branch
- Write tests for new features
- Ensure all tests pass
- Update documentation
- Keep PRs focused on a single change
- Follow conventional commit messages

## Reporting Bugs

Please use [GitHub Issues](https://github.com/omrersen/spectre/issues) with:
- Clear description
- Steps to reproduce
- Expected vs actual behavior
- Environment info

## Security Issues

See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.
