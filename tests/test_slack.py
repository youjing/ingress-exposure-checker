import httpx
import respx
import pytest

from iec.models import Target, ScanResult, AuthStatus, TestDetail
from iec.report.slack import (
    build_slack_payload, env_name_from_file, send_slack,
)


@pytest.fixture
def sample_results():
    return [
        ScanResult(
            target=Target(url="http://app-a.example.com/kibana", name="kibana",
                          namespace="ns-observ"),
            middleware="kibana", auth_status=AuthStatus.EXPOSED_DEFAULT_CREDS,
            evidence=["kibana default creds worked: elastic/elastic"],
            details=[TestDetail(
                name="默认凭据测试", description="使用默认凭据尝试登录",
                credentials="elastic/elastic", vulnerable=True,
            )],
        ),
        ScanResult(
            target=Target(url="http://app-b.example.com/", name="nacos",
                          namespace="ns-config"),
            middleware="nacos", auth_status=AuthStatus.EXPOSED_NO_AUTH,
            evidence=["unauthenticated API access"],
            details=[TestDetail(
                name="未授权访问测试", description="匿名请求敏感 API",
                credentials="-", vulnerable=True,
            )],
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


def test_env_name_from_ingress_file():
    assert env_name_from_file("/x/y/services.cogiot.net.ingress.txt".replace("cogiot.net", "example.com")) == "services.example.com"
    assert env_name_from_file("stage.ingress.txt") == "stage"
    assert env_name_from_file("targets.txt") == "targets"


def test_payload_includes_only_critical_and_high(sample_results):
    payload = build_slack_payload(sample_results, env_name="demo-env", total_scanned=4)
    text = str(payload)
    assert "app-a.example.com" in text   # HIGH
    assert "app-b.example.com" in text   # CRITICAL
    assert "safe.example.com" not in text   # PROTECTED 排除
    assert "unknown.example.com" not in text  # UNKNOWN 排除


def test_payload_header_and_summary(sample_results):
    payload = build_slack_payload(sample_results, env_name="demo-env", total_scanned=4)
    blocks = payload["blocks"]
    assert blocks[0]["type"] == "header"
    assert "demo-env" in blocks[0]["text"]["text"]
    assert "🚨" in blocks[0]["text"]["text"] or "⚠️" in blocks[0]["text"]["text"]
    # fallback text 用于通知预览
    assert "demo-env" in payload["text"]
    assert "严重 1" in payload["text"] and "高危 1" in payload["text"]


def test_payload_shows_credentials(sample_results):
    payload = build_slack_payload(sample_results, env_name="demo-env", total_scanned=4)
    text = str(payload)
    assert "elastic/elastic" in text   # 漏洞凭据可见


def test_payload_block_limit(sample_results):
    many = []
    for i in range(40):
        many.append(ScanResult(
            target=Target(url=f"http://h{i}.example.com/", namespace=f"ns{i%3}"),
            middleware="nacos", auth_status=AuthStatus.EXPOSED_NO_AUTH,
            evidence=["x"]))
    payload = build_slack_payload(many, env_name="demo-env", total_scanned=40)
    assert len(payload["blocks"]) <= 50                    # Slack 上限
    assert "未展示" in str(payload)                        # 截断提示


@pytest.mark.asyncio
async def test_send_slack_success():
    with respx.mock:
        route = respx.post("https://hooks.slack.com/services/T000/B000/FAKE").mock(
            return_value=httpx.Response(200, text="ok"))
        ok, msg = await send_slack("https://hooks.slack.com/services/T000/B000/FAKE",
                                   {"text": "hi", "blocks": []})
        assert ok and route.called


@pytest.mark.asyncio
async def test_send_slack_failure():
    with respx.mock:
        respx.post("https://hooks.slack.com/services/T000/B000/FAKE").mock(
            return_value=httpx.Response(400, text="invalid_payload"))
        ok, msg = await send_slack("https://hooks.slack.com/services/T000/B000/FAKE",
                                   {"text": "hi"})
        assert not ok and "400" in msg
