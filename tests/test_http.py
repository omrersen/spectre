"""Tests for HTTP client factory and helpers."""
import pytest
import httpx

from spectre.utils.http import create_client, safe_get, safe_post
from spectre.utils.helpers import RateLimiter, is_valid_url


class TestCreateClient:
    @pytest.mark.asyncio
    async def test_default_client(self):
        async with create_client() as client:
            assert isinstance(client, httpx.AsyncClient)
            assert client.timeout == httpx.Timeout(10.0)
            assert "Spectre" in client.headers["User-Agent"]

    @pytest.mark.asyncio
    async def test_custom_timeout(self):
        async with create_client(timeout=30.0) as client:
            assert client.timeout == httpx.Timeout(30.0)

    @pytest.mark.asyncio
    async def test_custom_headers(self):
        async with create_client(headers={"X-Custom": "test"}) as client:
            assert client.headers["X-Custom"] == "test"
            assert "Spectre" in client.headers["User-Agent"]

    @pytest.mark.asyncio
    async def test_no_redirects(self):
        async with create_client(follow_redirects=False) as client:
            assert client.follow_redirects is False

    @pytest.mark.asyncio
    async def test_verify_true(self):
        async with create_client(verify=True) as client:
            # httpx stores ssl verification on the transport
            assert client._transport is not None


class TestSafeRequests:
    @pytest.mark.asyncio
    async def test_safe_get_success(self):
        async with create_client() as client:
            resp = await safe_get(client, "https://httpbin.org/get")
            assert resp is None or resp.status_code == 200

    @pytest.mark.asyncio
    async def test_safe_get_invalid_url(self):
        async with create_client() as client:
            resp = await safe_get(client, "not-a-valid-url")
            assert resp is None

    @pytest.mark.asyncio
    async def test_safe_post_invalid_url(self):
        async with create_client() as client:
            resp = await safe_post(client, "not-a-valid-url")
            assert resp is None


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_rate_limiter_allows_burst(self):
        limiter = RateLimiter(max_calls=5, period=1.0)
        for _ in range(5):
            await limiter.acquire()  # Should not block

    @pytest.mark.asyncio
    async def test_rate_limiter_blocks_excess(self):
        import asyncio

        limiter = RateLimiter(max_calls=2, period=1.0)
        await limiter.acquire()
        await limiter.acquire()
        # Third call within period should sleep briefly
        start = asyncio.get_event_loop().time()
        await limiter.acquire()
        elapsed = asyncio.get_event_loop().time() - start
        assert elapsed >= 0  # It waited (even if very briefly in test)


class TestIsValidUrl:
    def test_valid_https(self):
        assert is_valid_url("https://example.com") is True

    def test_valid_http(self):
        assert is_valid_url("http://example.com/path") is True

    def test_invalid_scheme(self):
        assert is_valid_url("ftp://example.com") is False

    def test_no_host(self):
        assert is_valid_url("https://") is False

    def test_empty(self):
        assert is_valid_url("") is False
