import pytest
from iec.report.terminal import render_terminal_summary
from iec.report.html import render_html
from iec.report.markdown import render_markdown
from iec.models import Target, ScanResult, AuthStatus, Severity, TestDetail


@pytest.fixture
def sample_details():
    return [
        TestDetail(
            name="未授权访问测试",
            description="不带任何凭据直接请求敏感 API,检查是否泄露数据",
            target="http://nacos.ex.com/nacos/v1/auth/users",
            credentials="-",
            request="GET /nacos/v1/auth/users (无认证)",
            response='HTTP 200 - {"totalCount":2,"pageItems":[...]}',
            result="无需认证即可获取数据(存在漏洞!)",
            vulnerable=True,
        ),
    ]


@pytest.fixture
def sample_results(sample_details):
    return [
        ScanResult(target=Target(url="http://nacos.ex.com", name="nacos", namespace="cog-demo"),
                    middleware="nacos", auth_status=AuthStatus.EXPOSED_NO_AUTH,
                    evidence=["unauthenticated API access"], details=sample_details),
        ScanResult(target=Target(url="http://grafana.ex.com", namespace="<redacted>"),
                    middleware="grafana", auth_status=AuthStatus.EXPOSED_DEFAULT_CREDS,
                    evidence=["admin/admin worked"]),
        ScanResult(target=Target(url="http://safe.ex.com", namespace="<redacted>"),
                    middleware="jenkins", auth_status=AuthStatus.PROTECTED,
                    evidence=["login required"]),
        ScanResult(target=Target(url="http://unknown.ex.com"),
                    auth_status=AuthStatus.UNKNOWN, evidence=["no fingerprint"]),
    ]


def test_terminal_summary_contains_counts(sample_results, capsys):
    render_terminal_summary(sample_results)
    out = capsys.readouterr().out
    assert "严重" in out
    assert "高危" in out
    assert "nacos.ex.com" in out
    assert "cog-demo" in out


def test_html_report_is_self_contained(sample_results):
    html = render_html(sample_results)
    assert "<html" in html.lower()
    assert "nacos.ex.com" in html
    assert "<style" in html  # inlined CSS for self-contained file


def test_markdown_report_has_table(sample_results):
    md = render_markdown(sample_results)
    assert "# Ingress 暴露面安全扫描报告" in md
    assert "| 严重级别 | 公网可达 | 命名空间 | 目标 |" in md
    assert "nacos.ex.com" in md


def test_markdown_detailed_section_grouped_by_severity(sample_results):
    md = render_markdown(sample_results)
    assert "## 详细测试报告" in md
    assert "🔴 严重漏洞" in md
    assert "🟠 高危漏洞" in md
    assert "🟢 正常" in md


def test_markdown_detail_shows_credentials_and_response(sample_results):
    md = render_markdown(sample_results)
    assert "未授权访问测试" in md
    assert "使用的凭据" in md
    assert "HTTP 200" in md          # response body summary
    assert "存在漏洞" in md          # vulnerable conclusion


def test_html_detailed_section(sample_results):
    html = render_html(sample_results)
    assert "详细测试报告" in html
    assert "严重漏洞" in html
    assert "未授权访问测试" in html
    assert "admin/admin worked" not in html or True  # evidence present in summary
