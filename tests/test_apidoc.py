import httpx
import respx
import pytest

from iec.http import HttpClient
from iec.models import Target
from iec.probe import build_context
from iec.plugins.apidoc import (
    SwaggerPlugin, ActuatorPlugin, probe_api_docs,
    find_openapi_spec, find_actuator,
)
from iec.models import AuthStatus


HTML_PAGE = "<html><body>generic spa gateway page</body></html>"

OPENAPI_JSON = '{"openapi":"3.0.1","info":{"title":"Demo API","version":"1.0"},"paths":{}}'
SWAGGER2_JSON = '{"swagger":"2.0","info":{"title":"Demo"},"paths":{}}'
ACTUATOR_LINKS = '{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"}}}'
ACTUATOR_ENV = '{"activeProfiles":["prod"],"propertySources":[{"name":"x"}]}'
ACTUATOR_HEALTH = '{"status":"UP"}'


def _mock_home(base):
    respx.get(base + "/").mock(return_value=httpx.Response(200, text=HTML_PAGE))
    respx.get(base + "/favicon.ico").mock(return_value=httpx.Response(404))


@pytest.mark.asyncio
async def test_openapi_spec_exposed():
    target = Target(url="http://app.example.com")
    with respx.mock:
        _mock_home("http://app.example.com")
        respx.get("http://app.example.com/v3/api-docs").mock(
            return_value=httpx.Response(200, text=OPENAPI_JSON, headers={"Content-Type": "application/json"}))
        # 其余 spec 路径 404
        for p in ["/v2/api-docs", "/api-docs", "/swagger.json", "/v2/swagger.json",
                  "/openapi.json", "/v3/api-docs/swagger.json"]:
            respx.get("http://app.example.com" + p).mock(return_value=httpx.Response(404, text="nf"))
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            path, summary = await find_openapi_spec(ctx)
            assert path == "/v3/api-docs"
            result = await SwaggerPlugin().check_auth(ctx)
            assert result.status == AuthStatus.EXPOSED_NO_AUTH
            assert result.details[0].vulnerable is True


@pytest.mark.asyncio
async def test_swagger_ui_page_detected():
    target = Target(url="http://app.example.com")
    ui_html = '<html><head><title>Swagger UI</title></head><body>swagger-ui-bundle.js</body></html>'
    with respx.mock:
        _mock_home("http://app.example.com")
        for p in ["/v3/api-docs", "/v2/api-docs", "/api-docs", "/swagger.json",
                  "/v2/swagger.json", "/openapi.json", "/v3/api-docs/swagger.json"]:
            respx.get("http://app.example.com" + p).mock(return_value=httpx.Response(404, text="nf"))
        respx.get("http://app.example.com/swagger-ui.html").mock(
            return_value=httpx.Response(200, text=ui_html))
        respx.get("http://app.example.com/swagger-ui/index.html").mock(return_value=httpx.Response(404))
        respx.get("http://app.example.com/swagger-ui/").mock(return_value=httpx.Response(404))
        respx.get("http://app.example.com/swagger/").mock(return_value=httpx.Response(404))
        respx.get("http://app.example.com/docs").mock(return_value=httpx.Response(404))
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            result = await SwaggerPlugin().check_auth(ctx)
            assert result.status == AuthStatus.EXPOSED_NO_AUTH
            assert "swagger-ui.html" in result.evidence[0]


@pytest.mark.asyncio
async def test_actuator_env_leak():
    target = Target(url="http://spring.example.com")
    with respx.mock:
        _mock_home("http://spring.example.com")
        respx.get("http://spring.example.com/actuator").mock(
            return_value=httpx.Response(200, text=ACTUATOR_LINKS,
                                        headers={"Content-Type": "application/json"}))
        respx.get("http://spring.example.com/actuator/env").mock(
            return_value=httpx.Response(200, text=ACTUATOR_ENV,
                                        headers={"Content-Type": "application/json"}))
        respx.get("http://spring.example.com/actuator/heapdump").mock(return_value=httpx.Response(404))
        respx.get("http://spring.example.com/actuator/health").mock(
            return_value=httpx.Response(200, text=ACTUATOR_HEALTH,
                                        headers={"Content-Type": "application/json"}))
        respx.get("http://spring.example.com/actuator/mappings").mock(return_value=httpx.Response(404))
        respx.get("http://spring.example.com/actuator/configprops").mock(return_value=httpx.Response(404))
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            base, hits, _ = await find_actuator(ctx)
            assert base == "/actuator"
            assert "/actuator/env" in hits
            result = await ActuatorPlugin().check_auth(ctx)
            assert result.status == AuthStatus.EXPOSED_NO_AUTH


@pytest.mark.asyncio
async def test_html_gateway_page_not_false_positive():
    """HTML 网关回退页即使包含关键词也不应误报(吸取 logstash 误报教训)。"""
    target = Target(url="http://gw.example.com/app")
    tricky_html = ('<html><head><title>App</title></head><body>'
                   'openapi swagger paths _links actuator</body></html>')
    with respx.mock:
        respx.get("http://gw.example.com/app").mock(
            return_value=httpx.Response(200, text=tricky_html))
        respx.get("http://gw.example.com/app/favicon.ico").mock(return_value=httpx.Response(404))
        # 所有探测路径都返回该 HTML 页(网关回退)
        respx.route(host="gw.example.com").mock(
            return_value=httpx.Response(200, text=tricky_html))
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            spec_path, _ = await find_openapi_spec(ctx)
            assert spec_path is None  # HTML 页不算 spec
            name, result = await probe_api_docs(ctx)
            assert name is None
            assert result.status == AuthStatus.UNKNOWN


@pytest.mark.asyncio
async def test_swagger_fingerprint_on_homepage():
    target = Target(url="http://ui.example.com")
    ui_html = '<html><head><title>Swagger UI</title></head></html>'
    with respx.mock:
        respx.get("http://ui.example.com/").mock(return_value=httpx.Response(200, text=ui_html))
        respx.get("http://ui.example.com/favicon.ico").mock(return_value=httpx.Response(404))
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            fp = await SwaggerPlugin().fingerprint(ctx)
            assert fp is not None and fp.middleware == "swagger"


@pytest.mark.asyncio
async def test_no_exposure_returns_unknown():
    target = Target(url="http://clean.example.com")
    with respx.mock:
        _mock_home("http://clean.example.com")
        respx.route(host="clean.example.com").mock(return_value=httpx.Response(404, text="nf"))
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            name, result = await probe_api_docs(ctx)
            assert name is None
