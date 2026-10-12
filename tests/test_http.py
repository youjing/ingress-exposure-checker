import httpx
import respx
import pytest
from iec.http import HttpClient


@pytest.mark.asyncio
async def test_get_returns_response():
    async with HttpClient() as client:
        with respx.mock:
            route = respx.get("http://example.com/").mock(return_value=httpx.Response(200, text="ok"))
            resp = await client.get("http://example.com/")
            assert resp.status_code == 200 and route.called


@pytest.mark.asyncio
async def test_post_sends_json():
    async with HttpClient() as client:
        with respx.mock:
            route = respx.post("http://example.com/login").mock(return_value=httpx.Response(200, json={"ok": True}))
            resp = await client.post("http://example.com/login", json={"u": "a"})
            assert resp.status_code == 200 and route.calls[0].request.content is not None


@pytest.mark.asyncio
async def test_timeout_marks_error():
    async with HttpClient(timeout=0.001) as client:
        with respx.mock:
            respx.get("http://slow.com/").mock(side_effect=httpx.TimeoutException("slow"))
            ok, err = await client.safe_get("http://slow.com/")
            assert ok is False and ("TimeoutException" in err or "timeout" in err.lower())


@pytest.mark.asyncio
async def test_concurrency_semaphore_value():
    async with HttpClient(concurrency=2) as client:
        assert client._sem._value == 2
