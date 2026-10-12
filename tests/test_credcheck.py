import httpx
import respx
import pytest
from iec.credcheck import check_default_creds, check_basic_auth, check_api_no_auth
from iec.http import HttpClient
from iec.probe import ProbeContext, build_context
from iec.models import Target, AuthStatus


def _home_and_favicon(target_url: str) -> None:
    """Register path-specific homepage + favicon mocks for a target.

    respx matches a bare host (no path) to every subpath, so a homepage
    route at ``host`` with no trailing slash would swallow every subpath
    request (favicon, probes). Keep the homepage route path-specific by
    appending ``/`` when the URL has no path. The favicon URL is derived
    the same way the probe does: ``urljoin(url + "/", "favicon.ico")``.
    """
    from urllib.parse import urljoin
    url = httpx.URL(target_url)
    # homepage URL as the probe requests it (path-specific, trailing slash on bare host)
    home_url = target_url if url.path not in (None, "", "/") else str(url.copy_with(path="/"))
    favicon_url = urljoin(target_url.rstrip("/") + "/", "favicon.ico")
    respx.get(home_url).mock(return_value=httpx.Response(200, text=""))
    respx.get(favicon_url).mock(return_value=httpx.Response(404))


@pytest.mark.asyncio
async def test_check_default_creds_success():
    target = Target(url="http://nacos.example.com/nacos/")
    with respx.mock:
        _home_and_favicon(target.url)
        respx.post("http://nacos.example.com/nacos/v1/auth/login").mock(
            side_effect=[
                httpx.Response(200, text="login invalid"),    # control (wrong)
                httpx.Response(200, text="accessToken: abc"),  # default creds success
            ]
        )
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            result = await check_default_creds(
                ctx, login_path="/nacos/v1/auth/login",
                user_field="username", password_field="password",
                creds=[("nacos", "nacos")],
                success_markers=["accessToken"],
                failure_markers=["login invalid", "invalid"],
            )
            assert result.status == AuthStatus.EXPOSED_DEFAULT_CREDS


@pytest.mark.asyncio
async def test_check_default_creds_protected():
    target = Target(url="http://grafana.example.com/login")
    with respx.mock:
        _home_and_favicon(target.url)
        respx.post("http://grafana.example.com/login").mock(
            side_effect=[
                httpx.Response(200, text="invalid user"),  # control
                httpx.Response(200, text="invalid user"),  # default also fails
            ]
        )
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            result = await check_default_creds(
                ctx, login_path="/login",
                user_field="user", password_field="password",
                creds=[("admin", "admin")],
                success_markers=["redirect to /"],
                failure_markers=["invalid"],
            )
            assert result.status == AuthStatus.PROTECTED


@pytest.mark.asyncio
async def test_check_default_creds_inconclusive():
    target = Target(url="http://x.example.com/login")
    with respx.mock:
        _home_and_favicon(target.url)
        respx.post("http://x.example.com/login").mock(
            return_value=httpx.Response(200, text="unexpected response")
        )
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            result = await check_default_creds(
                ctx, login_path="/login",
                user_field="user", password_field="password",
                creds=[("admin", "admin")],
                success_markers=["ok"],
                failure_markers=["invalid"],
            )
            assert result.status == AuthStatus.INCONCLUSIVE


@pytest.mark.asyncio
async def test_check_basic_auth_success():
    target = Target(url="http://rabbitmq.example.com/api/whoami")
    with respx.mock:
        from urllib.parse import urljoin
        respx.get(urljoin(target.url.rstrip("/") + "/", "favicon.ico")).mock(
            return_value=httpx.Response(404))
        # target.url == probe path, so the homepage fetch and the authed probe
        # hit the same URL. Homepage fetch consumes the 401 (build_context
        # does not assert on status); the authed probe gets the 200 success.
        route = respx.get("http://rabbitmq.example.com/api/whoami").mock(
            side_effect=[
                httpx.Response(401, headers={"WWW-Authenticate": "Basic"}),  # homepage fetch
                httpx.Response(200, json={"name": "guest", "tags": ["administrator"]}),  # authed probe
            ]
        )
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            result = await check_basic_auth(
                ctx, probe_path="/api/whoami", creds=[("guest", "guest")]
            )
            assert result.status == AuthStatus.EXPOSED_DEFAULT_CREDS
            assert route.call_count == 2


@pytest.mark.asyncio
async def test_check_api_no_auth_exposed():
    target = Target(url="http://es.example.com:9200")
    with respx.mock:
        _home_and_favicon(target.url)
        respx.get("http://es.example.com:9200/_cluster/health").mock(
            return_value=httpx.Response(200, json={"cluster_name": "test", "status": "green"})
        )
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            result = await check_api_no_auth(
                ctx, probe_paths=["/_cluster/health", "/_cat/indices"],
                success_markers=["cluster_name"],
            )
            assert result.status == AuthStatus.EXPOSED_NO_AUTH


@pytest.mark.asyncio
async def test_check_api_no_auth_protected():
    target = Target(url="http://prom.example.com")
    with respx.mock:
        _home_and_favicon(target.url)
        respx.get("http://prom.example.com/api/v1/status/buildinfo").mock(
            return_value=httpx.Response(401, text="unauthorized")
        )
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            result = await check_api_no_auth(
                ctx, probe_paths=["/api/v1/status/buildinfo"],
                success_markers=["buildinfo"],
            )
            assert result.status == AuthStatus.PROTECTED
