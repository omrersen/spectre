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
    
    return engine


@click.group()
@click.version_option(__version__)
def main():
    """🔮 Spectre - AI-Powered Security Scanner"""
    pass


@main.command()
@click.argument("target")
@click.option("--scanner", "-s", help="Comma-separated list of scanners to use")
@click.option("--full", "-f", is_flag=True, help="Run all scanners")
@click.option("--output", "-o", help="Output file")
@click.option("--format", "fmt", default="json", help="Output format")
def scan(target: str, scanner: str, full: bool, output: str, format: str):
    """Scan a target for vulnerabilities."""
    engine = create_engine()
    
    scanners = None
    if scanner:
        scanners = [s.strip() for s in scanner.split(",")]
    elif not full:
        scanners = ["web", "tech", "ssl"]  # Default scanners
    
    result = asyncio.run(engine.scan(target, scanners))
    
    # Print summary
    console.print("\n[bold]Scan Summary[/bold]")
    console.print(f"Target: {result.target}")
    console.print(f"Duration: {result.duration:.1f}s")
    console.print(f"Findings: {len(result.findings)}")
    
    # Severity table
    table = Table(title="Findings by Severity")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    
    summary = result.summary
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = summary.get(sev, 0)
        color = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "blue",
            "info": "cyan"
        }.get(sev, "white")
        table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))
    
    console.print(table)
    
    # Show findings
    if result.findings:
        console.print("\n[bold]Detailed Findings[/bold]")
        for finding in result.findings[:10]:  # Show first 10
            color = {
                "critical": "red",
                "high": "orange1",
                "medium": "yellow",
                "low": "blue",
                "info": "cyan"
            }.get(finding.severity, "white")
            console.print(f"\n[{color}]{finding.severity.upper()}[/{color}] {finding.title}")
            console.print(f"  Target: {finding.target}")
            if finding.evidence:
                console.print(f"  Evidence: {finding.evidence}")
    
    # Save output
    if output:
        output_path = Path(output)
        if format == "json":
            output_path.write_text(result.model_dump_json(indent=2))
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
@click.option("--format", "fmt", default="html", help="Output format")
def report(results_file: str, output: str, format: str):
    """Generate a report from scan results."""
    from spectre.reporting import generate_report
    
    data = json.loads(Path(results_file).read_text())
    report_content = generate_report(data, format)
    
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


if __name__ == "__main__":
    main()
