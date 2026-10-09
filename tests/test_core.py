"""Tests for Spectre core."""
import pytest

from spectre.models import Finding, ScanResult, Severity
from spectre.utils.helpers import extract_host, shannon_entropy, redact_secret


class TestFinding:
    def test_finding_creation(self):
        f = Finding(
            title="SQL Injection",
            severity=Severity.CRITICAL,
            target="https://example.com/api?id=1",
            evidence="' OR 1=1--",
        )
        assert f.title == "SQL Injection"
        assert f.severity == "critical"
        assert f.verified is False
        assert f.false_positive is False

    def test_finding_defaults(self):
        f = Finding(title="Test", severity=Severity.INFO, target="test.com")
        assert f.evidence == ""
        assert f.cvss is None
        assert f.cve == []


class TestScanResult:
    def test_summary(self):
        result = ScanResult(target="example.com")
        result.findings = [
            Finding(title="A", severity=Severity.CRITICAL, target="t"),
            Finding(title="B", severity=Severity.CRITICAL, target="t"),
            Finding(title="C", severity=Severity.HIGH, target="t"),
            Finding(title="D", severity=Severity.LOW, target="t"),
        ]
        summary = result.summary
        assert summary["critical"] == 2
        assert summary["high"] == 1
        assert summary["low"] == 1
        assert result.critical_count == 2
        assert result.high_count == 1


class TestHelpers:
    def test_extract_host(self):
        assert extract_host("https://example.com/path") == "example.com"
        assert extract_host("http://sub.example.com:8080") == "sub.example.com"
        assert extract_host("example.com") == "example.com"

    def test_shannon_entropy(self):
        assert shannon_entropy("aaaa") == 0.0
        assert shannon_entropy("abcdefgh") > 2.9
        assert shannon_entropy("") == 0.0

    def test_redact_secret(self):
        assert redact_secret("abcd1234efgh5678") == "abcd...5678"
        assert redact_secret("short") == "*****"


class TestPluginSystem:
    def test_register_and_list(self):
        from spectre.plugins import PluginBase, register, get_plugin, list_plugins

        @register
        class DummyPlugin(PluginBase):
            name = "dummy-test-plugin"

            async def scan(self, target: str):
                return []

        assert "dummy-test-plugin" in list_plugins()
        assert get_plugin("dummy-test-plugin") is DummyPlugin
        assert get_plugin("nonexistent") is None


class TestReporting:
    def test_json_report(self):
        from spectre.reporting import generate_report

        data = {"target": "example.com", "findings": [], "duration": 1.0}
        out = generate_report(data, "json")
        assert "example.com" in out

    def test_markdown_report(self):
        from spectre.reporting import generate_report

        data = {
            "target": "example.com",
            "findings": [
                {"title": "XSS", "severity": "high", "target": "example.com", "evidence": "<script>"}
            ],
            "duration": 1.0,
        }
        out = generate_report(data, "markdown")
        assert "Spectre Scan Report" in out
        assert "XSS" in out

    def test_html_report(self):
        from spectre.reporting import generate_report

        data = {"target": "example.com", "findings": [], "duration": 1.0}
        out = generate_report(data, "html")
        assert "<!DOCTYPE html>" in out
        assert "Spectre" in out
