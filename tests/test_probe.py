import httpx
import respx
import pytest
from iec.http import HttpClient
from iec.models import Target
from iec.probe import ProbeContext, build_context

@pytest.mark.asyncio
async def test_build_context_fetches_home_and_favicon():
    target = Target(url="http://example.com")
    with respx.mock:
        respx.get("http://example.com/").mock(return_value=httpx.Response(200, text="<html>hi</html>"))
        respx.get("http://example.com/favicon.ico").mock(return_value=httpx.Response(200, content=b"x"))
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            assert ctx.home_body == "<html>hi</html>" and ctx.favicon_hash is not None

@pytest.mark.asyncio
async def test_build_context_handles_favicon_failure():
    target = Target(url="http://example.com")
    with respx.mock:
        respx.get("http://example.com/").mock(return_value=httpx.Response(200, text="ok"))
        respx.get("http://example.com/favicon.ico").mock(return_value=httpx.Response(404))
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            assert ctx.home_body == "ok" and ctx.favicon_hash is None

@pytest.mark.asyncio
async def test_context_fetch_path():
    target = Target(url="http://example.com")
    with respx.mock:
        respx.get("http://example.com/").mock(return_value=httpx.Response(200, text="home"))
        respx.get("http://example.com/favicon.ico").mock(return_value=httpx.Response(404))
        respx.get("http://example.com/api/health").mock(
            return_value=httpx.Response(200, text='{"status":"ok"}', headers={"Content-Type": "application/json"}))
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            status, body, headers = await ctx.fetch_path("/api/health")
            assert status == 200 and '{"status":"ok"}' in body and headers.get("content-type") == "application/json"
