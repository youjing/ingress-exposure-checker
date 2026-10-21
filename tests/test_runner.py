import asyncio

import httpx
import pytest
import respx

from iec.models import AuthCheckResult, AuthStatus, FingerprintResult, Target
from iec.plugins.base import PLUGINS, MiddlewarePlugin
from iec.runner import scan_all, scan_target


class GrafanaPlugin(MiddlewarePlugin):
    name = "grafana"

    async def fingerprint(self, ctx):
        if "grafana" in (ctx.home_body or "").lower():
            return FingerprintResult(middleware="grafana", confidence="high", evidence=["body"])
        return None

    async def check_auth(self, ctx):
        return AuthCheckResult(status=AuthStatus.PROTECTED, evidence=["mock"])


@pytest.mark.asyncio
async def test_scan_target_matches_and_checks():
    snapshot = list(PLUGINS)
    PLUGINS.clear()
    PLUGINS.append(GrafanaPlugin())
    try:
        with respx.mock:
            respx.get("http://grafana.example.com/").mock(
                return_value=httpx.Response(200, text="<html>grafana</html>")
            )
            respx.get("http://grafana.example.com/favicon.ico").mock(
                return_value=httpx.Response(404)
            )
            result = await scan_target(Target(url="http://grafana.example.com/"))
            assert result.middleware == "grafana"
            assert result.auth_status == AuthStatus.PROTECTED
    finally:
        PLUGINS[:] = snapshot


@pytest.mark.asyncio
async def test_scan_target_unreachable():
    with respx.mock:
        respx.get("http://down.example.com/").mock(
            side_effect=httpx.ConnectError("down")
        )
        respx.get("http://down.example.com/favicon.ico").mock(
            side_effect=httpx.ConnectError("down")
        )
        result = await scan_target(Target(url="http://down.example.com/"))
        assert result.auth_status in (AuthStatus.UNREACHABLE, AuthStatus.ERROR)


@pytest.mark.asyncio
async def test_scan_all_runs_multiple():
    snapshot = list(PLUGINS)
    PLUGINS.clear()
    PLUGINS.append(GrafanaPlugin())
    try:
        with respx.mock:
            respx.get("http://g1.example.com/").mock(
                return_value=httpx.Response(200, text="grafana")
            )
            respx.get("http://g1.example.com/favicon.ico").mock(
                return_value=httpx.Response(404)
            )
            respx.get("http://g2.example.com/").mock(
                return_value=httpx.Response(200, text="grafana")
            )
            respx.get("http://g2.example.com/favicon.ico").mock(
                return_value=httpx.Response(404)
            )
            results = await scan_all(
                [Target(url="http://g1.example.com/"), Target(url="http://g2.example.com/")],
                concurrency=5,
                timeout=5,
                on_found=None,
            )
            assert len(results) == 2
            assert all(r.middleware == "grafana" for r in results)
    finally:
        PLUGINS[:] = snapshot


@pytest.mark.asyncio
async def test_scan_target_404_no_service():
    with respx.mock:
        respx.get("http://gone.example.com/").mock(
            return_value=httpx.Response(404, text="<html>404 page</html>"))
        respx.get("http://gone.example.com/favicon.ico").mock(return_value=httpx.Response(404))
        result = await scan_target(Target(url="http://gone.example.com/"))
        assert result.auth_status == AuthStatus.NOT_FOUND
        assert result.reachable is True
        assert result.middleware is None


@pytest.mark.asyncio
async def test_scan_target_5xx_not_reachable():
    with respx.mock:
        respx.get("http://gwerr.example.com/").mock(
            return_value=httpx.Response(502, text="Bad Gateway"))
        respx.get("http://gwerr.example.com/favicon.ico").mock(return_value=httpx.Response(502))
        result = await scan_target(Target(url="http://gwerr.example.com/"))
        assert result.auth_status == AuthStatus.UNREACHABLE
        assert result.reachable is False
