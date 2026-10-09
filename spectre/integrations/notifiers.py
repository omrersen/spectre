"""Notification integrations for Spectre."""
from __future__ import annotations

import json
from typing import Any

import httpx

from spectre.models import ScanResult, Severity


class SlackNotifier:
    """Send scan results to Slack via incoming webhook."""

    def __init__(self, webhook_url: str, channel: str | None = None):
        self.webhook_url = webhook_url
        self.channel = channel

    async def notify(self, result: ScanResult) -> bool:
        summary = result.summary
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🔮 Spectre Scan Complete"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n{result.target}"},
                    {"type": "mrkdwn", "text": f"*Duration:*\n{result.duration:.1f}s"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Critical:* {summary.get('critical', 0)}  "
                        f"*High:* {summary.get('high', 0)}  "
                        f"*Medium:* {summary.get('medium', 0)}  "
                        f"*Low:* {summary.get('low', 0)}  "
                        f"*Info:* {summary.get('info', 0)}"
                    ),
                },
            },
        ]

        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        if critical:
            lines = "\n".join(f"• {f.title} @ {f.target}" for f in critical[:5])
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f":rotating_light: *Critical Findings:*\n{lines}"},
                }
            )

        payload: dict[str, Any] = {"blocks": blocks}
        if self.channel:
            payload["channel"] = self.channel

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(self.webhook_url, json=payload)
            return resp.status_code == 200


class DiscordNotifier:
    """Send scan results to Discord via webhook."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    async def notify(self, result: ScanResult) -> bool:
        summary = result.summary
        color = 0xDC2626 if summary.get("critical", 0) else 0xEA580C if summary.get("high", 0) else 0x2563EB

        embed = {
            "title": "🔮 Spectre Scan Complete",
            "color": color,
            "fields": [
                {"name": "Target", "value": result.target, "inline": True},
                {"name": "Duration", "value": f"{result.duration:.1f}s", "inline": True},
                {
                    "name": "Findings",
                    "value": (
                        f"🔴 {summary.get('critical', 0)} critical | "
                        f"🟠 {summary.get('high', 0)} high | "
                        f"🟡 {summary.get('medium', 0)} medium | "
                        f"🔵 {summary.get('low', 0)} low"
                    ),
                    "inline": False,
                },
            ],
            "footer": {"text": "Spectre Security Scanner"},
        }

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(self.webhook_url, json={"embeds": [embed]})
            return resp.status_code in (200, 204)


class WebhookNotifier:
    """Generic webhook notification."""

    def __init__(self, url: str, headers: dict[str, str] | None = None):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}

    async def notify(self, result: ScanResult) -> bool:
        payload = result.model_dump(mode="json")
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(self.url, json=payload, headers=self.headers)
            return resp.status_code < 400
