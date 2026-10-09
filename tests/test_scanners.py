"""Integration tests: all scanner classes instantiate and expose correct metadata."""
import pytest

from spectre.scanners.web import WebScanner
from spectre.scanners.subdomain import SubdomainScanner
from spectre.scanners.port import PortScanner
from spectre.scanners.secrets import SecretsScanner
from spectre.scanners.tech import TechScanner
from spectre.scanners.ssl import SSLScanner
from spectre.scanners.dirscan import DirScanner
from spectre.scanners.cve import CVEScanner
from spectre.scanners.waf import WAFScanner
from spectre.scanners.archive import ArchiveScanner
from spectre.scanners.robots import RobotsScanner
from spectre.scanners.base import BaseScanner


ALL_SCANNERS = [
    WebScanner,
    SubdomainScanner,
    PortScanner,
    SecretsScanner,
    TechScanner,
    SSLScanner,
    DirScanner,
    CVEScanner,
    WAFScanner,
    ArchiveScanner,
    RobotsScanner,
]


class TestScannerRegistry:
    @pytest.mark.parametrize("cls", ALL_SCANNERS)
    def test_instantiates(self, cls):
        instance = cls()
        assert isinstance(instance, BaseScanner)

    @pytest.mark.parametrize("cls", ALL_SCANNERS)
    def test_has_metadata(self, cls):
        instance = cls()
        assert instance.name
        assert instance.description
        assert instance.version

    @pytest.mark.parametrize("cls", ALL_SCANNERS)
    def test_name_is_unique(self, cls):
        instance = cls()
        names = [c().name for c in ALL_SCANNERS]
        assert names.count(instance.name) == 1

    @pytest.mark.parametrize("cls", ALL_SCANNERS)
    def test_scan_is_async(self, cls):
        import inspect

        instance = cls()
        assert inspect.iscoroutinefunction(instance.scan)

    def test_engine_registers_all(self):
        from spectre.cli import create_engine

        engine = create_engine()
        names = [s.name for s in engine.scanners]
        assert "web" in names
        assert "subdomain" in names
        assert "secrets" in names
        assert "port" in names
        assert "tech" in names
        assert "ssl" in names
        assert "dirscan" in names
        assert "cve" in names

    def test_dirscan_wordlist(self):
        scanner = DirScanner()
        assert len(scanner.WORDLIST) >= 100

    def test_cve_has_cpe_map(self):
        scanner = CVEScanner()
        assert len(scanner.CPE_MAP) >= 10

    def test_secrets_has_patterns(self):
        scanner = SecretsScanner()
        assert len(scanner.PATTERNS) >= 20

    def test_port_has_common_ports(self):
        scanner = PortScanner()
        assert len(scanner.COMMON_PORTS) >= 100

    def test_tech_has_fingerprints(self):
        scanner = TechScanner()
        assert len(scanner.FINGERPRINTS) >= 40
