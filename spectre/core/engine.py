import asyncio
import time
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from spectre.models import Finding, ScanResult, Severity
from spectre.scanners.base import BaseScanner
from spectre.utils.helpers import RateLimiter

console = Console()


class ScanEngine:
    """Core scanning engine with async support."""
    
    def __init__(
        self,
        max_concurrent: int = 50,
        timeout: int = 30,
        proxy: str | None = None,
        rate_limit: int = 0,
    ):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.proxy = proxy or None
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.scanners: list[BaseScanner] = []
        # Global rate limiter (requests per second), disabled when 0
        self.rate_limiter = RateLimiter(max_calls=rate_limit, period=1.0) if rate_limit > 0 else None
    
    def register_scanner(self, scanner: BaseScanner):
        """Register a scanner with the engine."""
        if self.proxy and hasattr(scanner, "proxy"):
            scanner.proxy = self.proxy
        if self.rate_limiter and hasattr(scanner, "rate_limiter"):
            scanner.rate_limiter = self.rate_limiter
        self.scanners.append(scanner)
    
    async def scan(self, target: str, scanners: list[str] | None = None) -> ScanResult:
        """Run all registered scanners against a target."""
        start_time = time.time()
        
        # Filter scanners if specific ones requested
        active_scanners = self.scanners
        if scanners:
            active_scanners = [s for s in self.scanners if s.name in scanners]
        
        result = ScanResult(target=target, scanners_used=[s.name for s in active_scanners])
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            tasks = []
            for scanner in active_scanners:
                task = progress.add_task(f"Running {scanner.name}...", total=None)
                scan_task = self._run_scanner(scanner, target, task, progress)
                tasks.append(scan_task)
            
            # Run all scanners concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect findings
            for scan_result in results:
                if isinstance(scan_result, list):
                    result.findings.extend(scan_result)
                elif isinstance(scan_result, Exception):
                    console.print(f"[red]Error: {scan_result}[/red]")
        
        result.duration = time.time() - start_time
        return result
    
    async def _run_scanner(
        self, scanner: BaseScanner, target: str, task_id: int, progress: Progress
    ) -> list[Finding]:
        """Run a single scanner with concurrency control."""
        async with self.semaphore:
            try:
                findings = await asyncio.wait_for(
                    scanner.scan(target), timeout=self.timeout
                )
                progress.update(task_id, description=f"[green]✓ {scanner.name}[/green]")
                return findings
            except asyncio.TimeoutError:
                progress.update(task_id, description=f"[red]✗ {scanner.name} (timeout)[/red]")
                return []
            except Exception as e:
                progress.update(task_id, description=f"[red]✗ {scanner.name} ({e})[/red]")
                return []
    
    async def scan_multiple(
        self, targets: list[str], scanners: list[str] | None = None
    ) -> list[ScanResult]:
        """Scan multiple targets concurrently."""
        tasks = [self.scan(target, scanners) for target in targets]
        return await asyncio.gather(*tasks)
