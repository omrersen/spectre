"""AI-powered vulnerability analysis and false positive reduction."""
from __future__ import annotations

import json
import os
from typing import Any

from spectre.models import Finding, ScanResult


class AIAnalyzer:
    """LLM-powered analysis of scan results.

    Supported providers:

    - ``openai``: OpenAI API (requires ``OPENAI_API_KEY``).
    - ``anthropic``: Anthropic API (requires ``ANTHROPIC_API_KEY``).
    - ``ollama``: Local models served by Ollama via its HTTP API.
      Defaults to ``http://localhost:11434`` (override with the ``host``
      parameter or the ``OLLAMA_HOST`` environment variable). Uses no API
      key; call :meth:`list_models` to discover installed models.
    """

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4",
        host: str | None = None,
    ):
        self.provider_name = provider
        self.model_name = model
        self.host = host or os.environ.get("OLLAMA_HOST") or "http://localhost:11434"
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
        elif self.provider_name == "ollama":
            # No SDK client — Ollama is called directly over HTTP with httpx.
            return None
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

        if self.provider_name == "ollama":
            return await self._call_ollama(prompt)

        raise ValueError(f"Unsupported provider: {self.provider_name}")

    async def _call_ollama(self, prompt: str) -> str:
        """Call the Ollama chat API (POST {host}/api/chat) via httpx."""
        import httpx

        model = self.model_name or "llama3.2"
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{self.host}/api/chat",
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": prompt}],
                        "stream": False,
                    },
                )
        except (httpx.HTTPError, OSError) as exc:
            raise RuntimeError(
                f"Could not reach Ollama at {self.host} "
                f"({exc.__class__.__name__}: {exc}). Is Ollama running? "
                "Start it with `ollama serve`, install a model with "
                f"`ollama pull {model}`, or point at another host via the "
                "OLLAMA_HOST environment variable or AIAnalyzer(host=...)."
            ) from exc

        if response.is_error:
            raise RuntimeError(
                f"Ollama at {self.host} returned HTTP {response.status_code} "
                f"for model '{model}': {response.text[:300]}. Is the model "
                f"installed? Try `ollama pull {model}` or check "
                "AIAnalyzer.list_models()."
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Ollama at {self.host} returned a non-JSON response: "
                f"{response.text[:200]}"
            ) from exc
        return (data.get("message") or {}).get("content", "")

    async def list_models(self) -> list[str]:
        """Return the names of models installed in Ollama (GET {host}/api/tags)."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"{self.host}/api/tags")
        except (httpx.HTTPError, OSError) as exc:
            raise RuntimeError(
                f"Could not reach Ollama at {self.host} "
                f"({exc.__class__.__name__}: {exc}). Is Ollama running? "
                "Start it with `ollama serve`, or point at another host via "
                "the OLLAMA_HOST environment variable or AIAnalyzer(host=...)."
            ) from exc

        if response.is_error:
            raise RuntimeError(
                f"Ollama at {self.host} returned HTTP {response.status_code} "
                f"from /api/tags: {response.text[:300]}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Ollama at {self.host} returned a non-JSON response: "
                f"{response.text[:200]}"
            ) from exc
        return [m.get("name", "") for m in data.get("models", []) if m.get("name")]

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
