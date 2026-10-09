"""Shared utility helpers for Spectre."""
from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar
from urllib.parse import urlparse

T = TypeVar("T")

DEFAULT_USER_AGENT = "Spectre/0.1.0 (Security Scanner)"


def extract_host(url: str) -> str:
    """Extract hostname from a URL or bare hostname."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or url


def is_valid_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.hostname)
    except Exception:
        return False


def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    import math

    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


async def retry_async(
    func: Callable[..., Coroutine[Any, Any, T]],
    *args: Any,
    retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    **kwargs: Any,
) -> T:
    """Retry an async function with exponential backoff."""
    last_exc: Exception | None = None
    current_delay = delay
    for attempt in range(retries):
        try:
            return await func(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt < retries - 1:
                await asyncio.sleep(current_delay)
                current_delay *= backoff
    raise last_exc  # type: ignore[misc]


class RateLimiter:
    """Simple async rate limiter."""

    def __init__(self, max_calls: int, period: float = 1.0):
        self.max_calls = max_calls
        self.period = period
        self._calls: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._calls = [t for t in self._calls if now - t < self.period]
            if len(self._calls) >= self.max_calls:
                sleep_time = self.period - (now - self._calls[0])
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                now = time.monotonic()
                self._calls = [t for t in self._calls if now - t < self.period]
            self._calls.append(time.monotonic())


def redact_secret(text: str) -> str:
    """Redact a secret value for safe display."""
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}...{text[-4:]}"
