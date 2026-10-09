"""Shared HTTP client factory for Spectre scanners."""
from __future__ import annotations

from typing import Any

import httpx

from spectre.utils.helpers import DEFAULT_USER_AGENT


def create_client(
    *,
    proxy: str | None = None,
    timeout: float = 10.0,
    follow_redirects: bool = True,
    verify: bool = False,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Create a pre-configured httpx.AsyncClient.

    All scanners should use this factory so proxy, timeout, and
    user-agent settings stay consistent with the global config.
    """
    merged_headers: dict[str, str] = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        merged_headers.update(headers)

    client_kwargs: dict[str, Any] = {
        "timeout": timeout,
        "follow_redirects": follow_redirects,
        "verify": verify,
        "headers": merged_headers,
    }
    if proxy:
        client_kwargs["proxy"] = proxy
    client_kwargs.update(kwargs)

    return httpx.AsyncClient(**client_kwargs)


async def safe_get(
    client: httpx.AsyncClient,
    url: str,
    **kwargs: Any,
) -> httpx.Response | None:
    """GET with error handling — returns None instead of raising."""
    try:
        return await client.get(url, **kwargs)
    except (httpx.HTTPError, httpx.InvalidURL):
        return None


async def safe_post(
    client: httpx.AsyncClient,
    url: str,
    **kwargs: Any,
) -> httpx.Response | None:
    """POST with error handling — returns None instead of raising."""
    try:
        return await client.post(url, **kwargs)
    except (httpx.HTTPError, httpx.InvalidURL):
        return None
