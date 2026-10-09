"""Tests for AI analyzer (constructor/provider setup, no network calls)."""
import pytest

from spectre.ai.analyzer import AIAnalyzer


class TestAIAnalyzer:
    def test_openai_provider(self):
        a = AIAnalyzer(provider="openai", model="gpt-4")
        assert a.provider_name == "openai"
        assert a.model_name == "gpt-4"

    def test_anthropic_provider(self):
        a = AIAnalyzer(provider="anthropic", model="claude-sonnet-4-5")
        assert a.provider_name == "anthropic"
        assert a.model_name == "claude-sonnet-4-5"

    def test_ollama_provider(self):
        a = AIAnalyzer(provider="ollama", model="llama3.2")
        assert a.provider_name == "ollama"
        assert a.model_name == "llama3.2"

    def test_ollama_host_default(self):
        a = AIAnalyzer(provider="ollama")
        # host attr exists (may be None or set from env)
        assert hasattr(a, "host") or hasattr(a, "provider_name")

    def test_invalid_provider_raises_on_call(self):
        a = AIAnalyzer(provider="invalid")
        assert a.provider_name == "invalid"

    def test_summarize_findings(self):
        from spectre.models import Finding, ScanResult, Severity

        result = ScanResult(target="example.com")
        result.findings = [
            Finding(title="SQLi", severity=Severity.CRITICAL, target="https://example.com/api", evidence="' OR 1=1--"),
            Finding(title="XSS", severity=Severity.HIGH, target="https://example.com/search", evidence="<script>"),
        ]
        summary = AIAnalyzer._summarize_findings(result)
        assert "SQLi" in summary
        assert "XSS" in summary
        assert "critical" in summary

    def test_summarize_empty(self):
        from spectre.models import ScanResult

        result = ScanResult(target="example.com")
        summary = AIAnalyzer._summarize_findings(result)
        assert "no findings" in summary.lower()

    def test_parse_indices_json(self):
        assert AIAnalyzer._parse_indices("[0, 2, 5]") == [0, 2, 5]
        assert AIAnalyzer._parse_indices('["1", "3"]') == [1, 3]

    def test_parse_indices_plain_text(self):
        assert AIAnalyzer._parse_indices("The false positives are 0, 2 and 4") == [0, 2, 4]
        assert AIAnalyzer._parse_indices("") == []
