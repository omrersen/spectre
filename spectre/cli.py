import asyncio
import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from spectre import __version__
from spectre.core.engine import ScanEngine
from spectre.models import Severity

console = Console()

# Import scanners
from spectre.scanners.web import WebScanner
from spectre.scanners.subdomain import SubdomainScanner
from spectre.scanners.secrets import SecretsScanner
from spectre.scanners.port import PortScanner
from spectre.scanners.tech import TechScanner
from spectre.scanners.ssl import SSLScanner

# Optional scanners (may not be installed in minimal setups)
try:
    from spectre.scanners.dirscan import DirScanner
except ImportError:
    DirScanner = None

try:
    from spectre.scanners.cve import CVEScanner
except ImportError:
    CVEScanner = None


def create_engine() -> ScanEngine:
    """Create and configure the scan engine."""
    engine = ScanEngine()
    
    # Register all scanners
    engine.register_scanner(WebScanner())
    engine.register_scanner(SubdomainScanner())
    engine.register_scanner(SecretsScanner())
    engine.register_scanner(PortScanner())
    engine.register_scanner(TechScanner())
    engine.register_scanner(SSLScanner())
    
    # Register optional scanners
    if DirScanner is not None:
        engine.register_scanner(DirScanner())
    if CVEScanner is not None:
        engine.register_scanner(CVEScanner())
    
    return engine


@click.group()
@click.version_option(__version__)
def main():
    """🔮 Spectre - AI-Powered Security Scanner"""
    pass


@main.command()
@click.argument("target", required=False)
@click.option("--file", "-F", "file_path", help="File containing list of targets (one per line)")
@click.option("--scanner", "-s", help="Comma-separated list of scanners to use")
@click.option("--full", "-f", is_flag=True, help="Run all scanners")
@click.option("--parallel", "-p", is_flag=True, help="Scan multiple targets in parallel (with -F)")
@click.option("--output", "-o", help="Output file")
@click.option("--format", "fmt", default="json", help="Output format (json, markdown, html, sarif)")
@click.option("--ai", is_flag=True, help="Enable AI-powered analysis")
def scan(target: str, file_path: str, scanner: str, full: bool, parallel: bool, output: str, fmt: str, ai: bool):
    """Scan a target for vulnerabilities. Use -F to scan multiple targets from a file."""
    engine = create_engine()
    
    scanners = None
    if scanner:
        scanners = [s.strip() for s in scanner.split(",")]
    elif not full:
        scanners = ["web", "tech", "ssl"]  # Default scanners
    
    # Load targets from file
    targets: list[str] = []
    if file_path:
        lines = Path(file_path).read_text().strip().splitlines()
        targets = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    elif target:
        targets = [target]
    else:
        console.print("[red]Error: provide a target or use -F <file>[/red]")
        return
    
    # Single target
    if len(targets) == 1:
        result = asyncio.run(engine.scan(targets[0], scanners))
        results = [result]
    # Multiple targets
    elif parallel:
        results = asyncio.run(engine.scan_multiple(targets, scanners))
    else:
        results = []
        for t in targets:
            results.append(asyncio.run(engine.scan(t, scanners)))
    
    # Print summary for each result
    all_findings = []
    for result in results:
        all_findings.extend(result.findings)
        
        console.print(f"\n[bold]Scan: {result.target}[/bold]")
        console.print(f"  Duration: {result.duration:.1f}s | Findings: {len(result.findings)}")
        
        summary = result.summary
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = summary.get(sev, 0)
            if count > 0:
                color = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "blue", "info": "cyan"}.get(sev, "white")
                console.print(f"  [{color}]{sev.upper()}[/{color}]: {count}")
    
    # Combined severity table
    if len(results) > 1:
        console.print(f"\n[bold]Combined: {len(all_findings)} findings across {len(results)} targets[/bold]")
    
    # Show critical/high findings
    severe = [f for f in all_findings if f.severity in ("critical", "high")]
    if severe:
        console.print("\n[bold red]Critical/High Findings:[/bold red]")
        for f in severe[:20]:
            color = "red" if f.severity == "critical" else "orange1"
            console.print(f"[{color}]{f.severity.upper()}[/{color}] {f.title}")
            console.print(f"  {f.target}")
            if f.evidence:
                console.print(f"  Evidence: {f.evidence[:150]}")
    
    # Save output
    if output:
        from spectre.reporting import generate_report
        
        if len(results) == 1:
            data = results[0].model_dump(mode="json")
        else:
            data = {
                "targets": [r.target for r in results],
                "findings": [f.model_dump(mode="json") for r in results for f in r.findings],
                "duration": sum(r.duration for r in results),
                "scanners_used": results[0].scanners_used if results else [],
            }
        
        report_content = generate_report(data, fmt)
        Path(output).write_text(report_content)
        console.print(f"\n[green]Results saved to {output}[/green]")


@main.command()
@click.argument("domain")
@click.option("--brute", is_flag=True, help="Enable brute force enumeration")
@click.option("--passive", is_flag=True, help="Passive enumeration only")
def subdomains(domain: str, brute: bool, passive: bool):
    """Enumerate subdomains for a domain."""
    scanner = SubdomainScanner()
    results = asyncio.run(scanner.scan(domain))
    
    console.print(f"\n[bold]Found {len(results)} subdomains[/bold]\n")
    for sub in sorted(set(r.target for r in results)):
        console.print(f"  • {sub}")


@main.command()
@click.argument("path")
@click.option("--pattern", help="Custom patterns (comma-separated)")
@click.option("--git-history", is_flag=True, help="Scan git history")
def secrets(path: str, pattern: str, git_history: bool):
    """Scan for secrets and API keys."""
    scanner = SecretsScanner()
    results = asyncio.run(scanner.scan(path))
    
    console.print(f"\n[bold]Found {len(results)} potential secrets[/bold]\n")
    for finding in results:
        console.print(f"[red]{finding.severity.upper()}[/red] {finding.title}")
        console.print(f"  File: {finding.target}")
        console.print(f"  Pattern: {finding.metadata.get('pattern', 'N/A')}")
        console.print()


@main.command()
@click.argument("results_file")
@click.option("--output", "-o", required=True, help="Output file")
@click.option("--format", "fmt", default="html", help="Output format (json, markdown, html, sarif)")
def report(results_file: str, output: str, fmt: str):
    """Generate a report from scan results."""
    from spectre.reporting import generate_report
    
    data = json.loads(Path(results_file).read_text())
    report_content = generate_report(data, fmt)
    
    Path(output).write_text(report_content)
    console.print(f"[green]Report generated: {output}[/green]")


@main.group()
def config():
    """Manage Spectre configuration."""
    pass


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str):
    """Set a configuration value."""
    from spectre.config import ConfigManager
    
    config_mgr = ConfigManager()
    config_mgr.set(key, value)
    console.print(f"[green]Set {key}[/green]")


@config.command("get")
@click.argument("key")
def config_get(key: str):
    """Get a configuration value."""
    from spectre.config import ConfigManager
    
    config_mgr = ConfigManager()
    value = config_mgr.get(key)
    console.print(value or "Not set")


@main.group()
def plugins():
    """Manage Spectre plugins."""
    pass


@plugins.command("list")
def plugins_list():
    """List available plugins."""
    from spectre.plugins import list_plugins, load_entry_point_plugins

    load_entry_point_plugins()
    names = list_plugins()

    if not names:
        console.print("[yellow]No plugins registered.[/yellow]")
        console.print("\nPlugins are discovered via entry points or ~/.spectre/plugins/")
        return

    table = Table(title="Registered Plugins")
    table.add_column("Name")
    table.add_column("Description")

    from spectre.plugins import get_plugin

    for name in names:
        cls = get_plugin(name)
        table.add_row(name, getattr(cls, "description", ""))

    console.print(table)


@plugins.command("install")
@click.argument("source")
def plugins_install(source: str):
    """Install a plugin from a local directory or Git URL."""
    import subprocess
    import sys

    if source.startswith(("http://", "https://", "git+")):
        url = source.removeprefix("git+")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", url],
            capture_output=True,
            text=True,
        )
    else:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-e", source],
            capture_output=True,
            text=True,
        )

    if result.returncode == 0:
        console.print(f"[green]Plugin installed: {source}[/green]")
    else:
        console.print(f"[red]Installation failed:[/red]\n{result.stderr}")


if __name__ == "__main__":
    main()
