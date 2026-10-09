#!/usr/bin/env python3
"""Spectre programmatic API example.

Demonstrates how to use Spectre as a library instead of CLI.
"""
import asyncio

from spectre.core.engine import ScanEngine
from spectre.scanners.web import WebScanner
from spectre.scanners.tech import TechScanner
from spectre.scanners.ssl import SSLScanner
from spectre.scanners.dirscan import DirScanner
from spectre.scanners.cve import CVEScanner
from spectre.reporting import generate_report


async def main() -> None:
    # Create engine with concurrency + timeout
    engine = ScanEngine(max_concurrent=30, timeout=30)

    # Register only the scanners you need
    engine.register_scanner(WebScanner())
    engine.register_scanner(TechScanner())
    engine.register_scanner(SSLScanner())
    engine.register_scanner(DirScanner())
    engine.register_scanner(CVEScanner())

    # Scan a single target
    target = "https://example.com"
    print(f"Scanning {target} ...")
    result = await engine.scan(target)

    print(f"\nFound {len(result.findings)} findings in {result.duration:.1f}s")
    for sev, count in result.summary.items():
        if count:
            print(f"  {sev}: {count}")

    # Print severe findings
    severe = [f for f in result.findings if f.severity in ("critical", "high")]
    if severe:
        print("\nCritical/High:")
        for f in severe:
            print(f"  [{f.severity.upper()}] {f.title}")
            print(f"    {f.target}")
            if f.evidence:
                print(f"    Evidence: {f.evidence[:120]}")

    # Generate reports
    html = generate_report(result.model_dump(mode="json"), "html")
    with open("example-report.html", "w", encoding="utf-8") as fh:
        fh.write(html)
    print("\nReport saved to example-report.html")

    # Multi-target example
    print("\n--- Multi-target scan ---")
    targets = ["https://example.com", "https://httpbin.org"]
    results = await engine.scan_multiple(targets, scanners=["tech", "ssl"])
    for r in results:
        print(f"  {r.target}: {len(r.findings)} findings")


if __name__ == "__main__":
    asyncio.run(main())
