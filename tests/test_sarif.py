"""Tests for SARIF report generation."""
import json

from spectre.reporting import generate_report, _classify_rule


class TestSarifReport:
    def test_sarif_generation(self):
        data = {
            "target": "https://example.com",
            "findings": [
                {
                    "title": "SQL Injection detected",
                    "severity": "critical",
                    "target": "https://example.com/api?id=1",
                    "evidence": "' OR 1=1--",
                    "scanner": "web",
                    "cvss": 9.8,
                    "cve": [],
                    "remediation": "Use parameterized queries",
                },
                {
                    "title": "Missing X-Frame-Options header",
                    "severity": "low",
                    "target": "https://example.com",
                    "evidence": "Header not found",
                    "scanner": "web",
                },
            ],
            "duration": 1.5,
        }

        sarif_str = generate_report(data, "sarif")
        sarif = json.loads(sarif_str)

        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "Spectre"
        assert run["tool"]["driver"]["version"] == "0.1.0"

        results = run["results"]
        assert len(results) == 2

        # SQL Injection → critical → error level, classified rule
        sqli = results[0]
        assert sqli["ruleId"] == "spectre-sql-injection"
        assert sqli["level"] == "error"
        assert sqli["properties"]["severity"] == "critical"
        assert sqli["properties"]["cvss"] == 9.8

        # Missing header → low → note level
        header = results[1]
        assert header["ruleId"] == "spectre-missing-header"
        assert header["level"] == "note"

    def test_sarif_empty_findings(self):
        data = {"target": "example.com", "findings": [], "duration": 0.1}
        sarif = json.loads(generate_report(data, "sarif"))
        assert sarif["runs"][0]["results"] == []

    def test_classify_rule(self):
        assert _classify_rule("SQL Injection found") == "spectre-sql-injection"
        assert _classify_rule("Reflected XSS") == "spectre-xss"
        assert _classify_rule("SSRF via webhook") == "spectre-ssrf"
        assert _classify_rule("TLS 1.0 enabled") == "spectre-tls"
        assert _classify_rule("AWS key exposed") == "spectre-secret"
        assert _classify_rule("CVE-2021-44228 in Log4j") == "spectre-cve"
        assert _classify_rule("Something random") == "spectre-generic"

    def test_sarif_level_mapping(self):
        data = {
            "target": "example.com",
            "findings": [
                {"title": "a", "severity": "critical", "target": "t"},
                {"title": "b", "severity": "high", "target": "t"},
                {"title": "c", "severity": "medium", "target": "t"},
                {"title": "d", "severity": "low", "target": "t"},
                {"title": "e", "severity": "info", "target": "t"},
            ],
            "duration": 0,
        }
        sarif = json.loads(generate_report(data, "sarif"))
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        assert levels == ["error", "error", "warning", "note", "note"]


class TestConfigProxy:
    def test_config_has_proxy_fields(self):
        from spectre.config import Config

        c = Config()
        assert c.scan_proxy == ""
        assert c.scan_rate_limit == 0
        assert c.scan_retries == 3
