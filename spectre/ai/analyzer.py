"""AI-powered vulnerability analysis and false positive reduction."""
from __future__ import annotations

import json
from typing import Any

from spectre.models import Finding, ScanResult


class AIAnalyzer:
    """LLM-powered analysis of scan results."""

    def __init__(self, provider: str = "openai", model: str = "gpt-4"):
        self.provider_name = provider
        self.model_name = model
        self._client = None

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client

        if self.provider_name == "openai":
            import os

            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))
        elif self.provider_name == "anthropic":
            import os

            from anthropic import AsyncAnthropic
            self._client = AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
        else:
            raise ValueError(f"Unsupported provider: {self.provider_name}")

        return self._client

    async def analyze(self, result: ScanResult) -> str:
        """Generate a natural-language security summary."""
        findings_summary = self._summarize_findings(result)
        prompt = (
            "You are a senior penetration tester. Given the following scan results, "
            "write a concise executive summary highlighting the most critical risks, "
            "potential attack chains, and recommended remediation priorities.\n\n"
            f"Target: {result.target}\n"
            f"Findings:\n{findings_summary}\n\n"
            "Executive Summary:"
        )
        return await self._call_llm(prompt)

    async def reduce_false_positives(self, findings: list[Finding]) -> list[Finding]:
        """Ask the LLM to mark likely false positives."""
        if not findings:
            return findings

        payload = json.dumps(
            [f.model_dump(mode="json") for f in findings], default=str, indent=2
        )
        prompt = (
            "You are a security expert. Below is a JSON list of scanner findings. "
            "Identify which are likely FALSE POSITIVES based on the evidence provided. "
            "Return ONLY a JSON array of indices (0-based) that are false positives.\n\n"
            f"{payload}\n\nFalse positive indices:"
        )
        response = await self._call_llm(prompt)
        fp_indices = self._parse_indices(response)

        for idx in fp_indices:
            if 0 <= idx < len(findings):
                findings[idx].false_positive = True

        return findings

    async def suggest_exploit(self, finding: Finding) -> str:
        """Suggest a proof-of-concept approach for a finding."""
        prompt = (
            "You are a penetration tester. For the security finding below, "
            "describe a safe proof-of-concept validation approach. "
            "Do NOT provide weaponized exploits.\n\n"
            f"Title: {finding.title}\n"
            f"Severity: {finding.severity}\n"
            f"Target: {finding.target}\n"
            f"Evidence: {finding.evidence}\n\n"
            "PoC Approach:"
        )
        return await self._call_llm(prompt)

    async def _call_llm(self, prompt: str) -> str:
        client = self._get_client()

        if self.provider_name == "openai":
            response = await client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
                temperature=0.2,
            )
            return response.choices[0].message.content or ""

        if self.provider_name == "anthropic":
            response = await client.messages.create(
                model=self.model_name,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text if response.content else ""

        raise ValueError(f"Unsupported provider: {self.provider_name}")

    @staticmethod
    def _summarize_findings(result: ScanResult) -> str:
        lines = []
        for f in result.findings:
            lines.append(
                f"- [{f.severity}] {f.title} @ {f.target}"
                + (f" | Evidence: {f.evidence[:200]}" if f.evidence else "")
            )
        return "\n".join(lines) if lines else "(no findings)"

    @staticmethod
    def _parse_indices(text: str) -> list[int]:
        text = text.strip()
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [int(x) for x in data]
        except (json.JSONDecodeError, ValueError):
            pass
        import re
        return [int(m) for m in re.findall(r"\d+", text)]
