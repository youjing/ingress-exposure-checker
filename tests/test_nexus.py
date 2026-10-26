import httpx
import respx
import pytest

from iec.http import HttpClient
from iec.models import Target, AuthStatus
from iec.probe import build_context
from iec.plugins.nexus import NexusPlugin

NEXUS_HTML = "<html><title>Nexus Repository Manager</title></html>"
REPOS_JSON = (
    '[{"name":"<redacted>","type":"hosted","url":"https://nx:8443/repository/<redacted>"},'
    '{"name":"maven-public","type":"group","url":"https://nx:8443/repository/maven-public"}]'
)
SEARCH_JSON = (
    '{"items":[{"name":"<redacted>","version":"1.1.0","assets":'
    '[{"downloadUrl":"https://nx:8443/repository/<redacted>/com/<redacted>/sdk-1.1.0.jar"}]}]}'
)


def _mock_home(base):
    respx.get(base + "/").mock(return_value=httpx.Response(200, text=NEXUS_HTML))
    respx.get(base + "/favicon.ico").mock(return_value=httpx.Response(404))


@pytest.mark.asyncio
async def test_nexus_anonymous_download_exposed():
    base = "https://nexus.example.com"
    with respx.mock:
        _mock_home(base)
        respx.get(base + "/service/rest/v1/repositories").mock(
            return_value=httpx.Response(200, text=REPOS_JSON,
                                        headers={"Content-Type": "application/json"}))
        respx.get(base + "/service/rest/v1/search").mock(
            return_value=httpx.Response(200, text=SEARCH_JSON,
                                        headers={"Content-Type": "application/json"}))
        # search 返回的 downloadUrl 指向 nx:8443 (内部地址),
        # 插件必须改写到目标 origin 后下载
        respx.get(base + "/repository/<redacted>/com/<redacted>/sdk-1.1.0.jar").mock(
            return_value=httpx.Response(200, content=b"\x00\x01binary-jar-bytes" * 100,
                                        headers={"Content-Type": "application/java-archive"}))
        async with HttpClient() as client:
            ctx = await build_context(client, Target(url=base))
            result = await NexusPlugin().check_auth(ctx)
            assert result.status == AuthStatus.EXPOSED_NO_AUTH
            assert any("anonymous download ok" in e for e in result.evidence)
            names = [d.name for d in result.details]
            assert "匿名仓库列表测试" in names
            assert "匿名制品搜索测试" in names
            assert "匿名制品下载测试" in names
            dl = [d for d in result.details if d.name == "匿名制品下载测试"][0]
            assert dl.vulnerable is True
            assert "application/java-archive" in dl.response


@pytest.mark.asyncio
async def test_nexus_anonymous_disabled_then_creds():
    base = "https://nexus2.example.com"
    with respx.mock:
        _mock_home(base)
        respx.get(base + "/service/rest/v1/repositories").mock(
            return_value=httpx.Response(401, text='{"error":"unauthorized"}'))
        respx.get(base + "/service/rest/v1/status").mock(
            return_value=httpx.Response(401, text="unauthorized"))
        async with HttpClient() as client:
            ctx = await build_context(client, Target(url=base))
            result = await NexusPlugin().check_auth(ctx)
            assert result.status == AuthStatus.PROTECTED
            assert any(d.name == "匿名仓库列表测试" and not d.vulnerable
                       for d in result.details)


@pytest.mark.asyncio
async def test_nexus_repos_visible_but_download_unverified():
    """仓库列表可见但搜索无结果/下载未验证成功 → 降级为 INCONCLUSIVE, 不报严重。"""
    base = "https://nexus3.example.com"
    with respx.mock:
        _mock_home(base)
        respx.get(base + "/service/rest/v1/repositories").mock(
            return_value=httpx.Response(200, text=REPOS_JSON,
                                        headers={"Content-Type": "application/json"}))
        respx.get(base + "/service/rest/v1/search").mock(
            return_value=httpx.Response(200, text='{"items":[]}',
                                        headers={"Content-Type": "application/json"}))
        async with HttpClient() as client:
            ctx = await build_context(client, Target(url=base))
            result = await NexusPlugin().check_auth(ctx)
            # 仓库列表匿名可见是事实, 但下载未验证 → 不定级, 不报严重
            assert result.status == AuthStatus.INCONCLUSIVE


@pytest.mark.asyncio
async def test_nexus_empty_repo_list_protected():
    """匿名配置开启但返回空列表(无任何仓库权限) → 不算发现, 走默认凭据测试。"""
    base = "https://nexus-empty.example.com"
    with respx.mock:
        _mock_home(base)
        respx.get(base + "/service/rest/v1/repositories").mock(
            return_value=httpx.Response(200, text="[ ]",
                                        headers={"Content-Type": "application/json"}))
        respx.get(base + "/service/rest/v1/status").mock(
            return_value=httpx.Response(401, text="unauthorized"))
        async with HttpClient() as client:
            ctx = await build_context(client, Target(url=base))
            result = await NexusPlugin().check_auth(ctx)
            assert result.status == AuthStatus.PROTECTED
            empty_detail = [d for d in result.details
                            if d.name == "匿名仓库列表测试" and "空列表" in d.response]
            assert empty_detail and empty_detail[0].vulnerable is False


@pytest.mark.asyncio
async def test_nexus_html_fallback_not_treated_as_json():
    """HTML 网关回退页不应被误判为仓库列表(防误报)。"""
    base = "https://gw.example.com/nexus"
    tricky = ('<html><body>repositories <redacted> maven-public json</body></html>')
    with respx.mock:
        respx.get(base).mock(return_value=httpx.Response(200, text=tricky))
        respx.get(base + "/favicon.ico").mock(return_value=httpx.Response(404))
        respx.route(host="gw.example.com").mock(
            return_value=httpx.Response(200, text=tricky))
        async with HttpClient() as client:
            ctx = await build_context(client, Target(url=base))
            result = await NexusPlugin().check_auth(ctx)
            assert result.status != AuthStatus.EXPOSED_NO_AUTH
