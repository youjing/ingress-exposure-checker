import httpx
import respx
import pytest

from iec.models import Target, ScanResult, AuthStatus, TestDetail
from iec.report.alertmanager import (
    am_api_url, build_alerts, send_to_alertmanager,
)

AM_URL = "https://alertmanager.example.com"


@pytest.fixture
def sample_results():
    return [
        ScanResult(
            target=Target(url="http://app-a.example.com/kibana", name="kibana",
                          namespace="ns-observ"),
            middleware="kibana", auth_status=AuthStatus.EXPOSED_DEFAULT_CREDS,
            evidence=["kibana default creds worked: elastic/elastic"],
            details=[TestDetail(name="默认凭据测试", description="尝试登录",
                                credentials="elastic/elastic", vulnerable=True)],
        ),
        ScanResult(
            target=Target(url="http://app-b.example.com/", name="nacos",
                          namespace="ns-config"),
            middleware="nacos", auth_status=AuthStatus.EXPOSED_NO_AUTH,
            evidence=["unauthenticated API access"],
        ),
        ScanResult(
            target=Target(url="http://safe.example.com/", name="jenkins",
                          namespace="ns-ci"),
            middleware="jenkins", auth_status=AuthStatus.PROTECTED,
            evidence=["login required"],
        ),
        ScanResult(
            target=Target(url="http://unknown.example.com/"),
            auth_status=AuthStatus.UNKNOWN, evidence=["no fingerprint"],
        ),
    ]


def test_am_api_url_appends_path():
    assert am_api_url("https://am.example.com") == "https://am.example.com/api/v2/alerts"
    assert am_api_url("https://am.example.com/") == "https://am.example.com/api/v2/alerts"
    # 反代前缀场景
    assert (am_api_url("https://host.example.com/alertmanager")
            == "https://host.example.com/alertmanager/api/v2/alerts")


def test_build_alerts_only_critical_and_high(sample_results):
    alerts = build_alerts(sample_results, env_name="demo-env")
    assert len(alerts) == 2  # 1 critical + 1 high
    instances = [a["labels"]["instance"] for a in alerts]
    assert "http://app-b.example.com/" in instances     # critical 排前
    assert "http://app-a.example.com/kibana" in instances
    assert instances.index("http://app-b.example.com/") < instances.index("http://app-a.example.com/kibana")


def test_build_alerts_labels_and_annotations(sample_results):
    alerts = build_alerts(sample_results, env_name="demo-env")
    high = next(a for a in alerts if a["labels"]["severity"] == "high")
    assert high["labels"]["alertname"] == "IngressExposure"
    assert high["labels"]["instance"] == "http://app-a.example.com/kibana"
    assert high["labels"]["namespace"] == "ns-observ"
    assert high["labels"]["middleware"] == "kibana"
    assert high["labels"]["env"] == "demo-env"
    assert "高危" in high["annotations"]["summary"]
    assert "[凭据: elastic/elastic]" in high["annotations"]["description"]
    assert "kibana default creds worked" in high["annotations"]["description"]


def test_build_alerts_endsat_25h(sample_results):
    alerts = build_alerts(sample_results, env_name="demo-env", ends_hours=25.0)
    from datetime import datetime
    s = datetime.fromisoformat(alerts[0]["startsAt"].replace("Z", "+00:00"))
    e = datetime.fromisoformat(alerts[0]["endsAt"].replace("Z", "+00:00"))
    assert (e - s).total_seconds() == 25 * 3600


def test_build_alerts_custom_endsat_hours(sample_results):
    alerts = build_alerts(sample_results, env_name="demo-env", ends_hours=2.0)
    from datetime import datetime
    s = datetime.fromisoformat(alerts[0]["startsAt"].replace("Z", "+00:00"))
    e = datetime.fromisoformat(alerts[0]["endsAt"].replace("Z", "+00:00"))
    assert (e - s).total_seconds() == 2 * 3600


@pytest.mark.asyncio
async def test_send_with_basic_auth(sample_results):
    alerts = build_alerts(sample_results, env_name="demo-env")
    with respx.mock:
        route = respx.post(f"{AM_URL}/api/v2/alerts").mock(
            return_value=httpx.Response(200, text=""))
        ok, msg = await send_to_alertmanager(f"{AM_URL}/api/v2/alerts", alerts,
                                             user="amuser", password="ampass")
        assert ok and "2 条" in msg
        req = route.calls[0].request
        assert req.headers.get("Authorization", "").startswith("Basic ")
        sent = httpx.Request("POST", "http://x", content=req.content).read()
        assert b"app-b.example.com" in sent


@pytest.mark.asyncio
async def test_send_without_auth(sample_results):
    alerts = build_alerts(sample_results, env_name="demo-env")
    with respx.mock:
        route = respx.post(f"{AM_URL}/api/v2/alerts").mock(
            return_value=httpx.Response(200, text=""))
        ok, _ = await send_to_alertmanager(f"{AM_URL}/api/v2/alerts", alerts)
        assert ok
        assert "Authorization" not in route.calls[0].request.headers


@pytest.mark.asyncio
async def test_send_failure():
    with respx.mock:
        respx.post(f"{AM_URL}/api/v2/alerts").mock(
            return_value=httpx.Response(403, text="forbidden"))
        ok, msg = await send_to_alertmanager(f"{AM_URL}/api/v2/alerts",
                                             [{"labels": {}}])
        assert not ok and "403" in msg


@pytest.mark.asyncio
async def test_no_alerts_no_request():
    with respx.mock:
        route = respx.post(f"{AM_URL}/api/v2/alerts").mock(
            return_value=httpx.Response(200, text=""))
        ok, msg = await send_to_alertmanager(f"{AM_URL}/api/v2/alerts", [])
        assert ok and "未发送" in msg
        assert not route.called
