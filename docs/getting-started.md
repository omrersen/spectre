# Getting Started

## Installation

```bash
pip install spectre-scanner
```

Or from source:

```bash
git clone https://github.com/omrersen/spectre.git
cd spectre
pip install -e ".[dev,ai]"
```

## First Scan

```bash
# Quick scan with default scanners (web, tech, ssl)
spectre scan https://example.com

# Full scan
spectre scan https://example.com --full

# Specific scanners
spectre scan https://example.com --scanner web,secrets
```

## Multi-Target Scanning

```bash
# Scan targets from a file (one URL per line)
spectre scan -F targets.txt

# Parallel scan for speed
spectre scan -F targets.txt --parallel
```

`targets.txt` example:
```
https://example.com
https://app.example.com
https://api.example.com
```

## Configure AI (Optional)

```bash
export OPENAI_API_KEY="sk-..."
# or
export ANTHROPIC_API_KEY="sk-ant-..."
```

Then enable AI analysis:

```bash
spectre scan https://example.com --ai
```

## Generate Reports

```bash
# Save results as JSON
spectre scan https://example.com -o results.json --format json

# Generate HTML report from results
spectre report results.json -o report.html --format html

# Markdown report
spectre report results.json -o report.md --format markdown

# SARIF (GitHub code-scanning compatible)
spectre report results.json -o report.sarif --format sarif
```

## Next Steps

- [Configuration Reference](configuration.md)
- [Plugin Development](plugins.md)
- [API Reference](api.md)
