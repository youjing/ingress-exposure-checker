import pytest
from iec.report.terminal import render_terminal_summary
from iec.report.html import render_html
from iec.report.markdown import render_markdown
from iec.models import Target, ScanResult, AuthStatus, Severity


@pytest.fixture
def sample_results():
    return [
        ScanResult(target=Target(url="http://nacos.ex.com", name="nacos"),
                    middleware="nacos", auth_status=AuthStatus.EXPOSED_NO_AUTH,
                    evidence=["unauthenticated API access"]),
        ScanResult(target=Target(url="http://grafana.ex.com"),
                    middleware="grafana", auth_status=AuthStatus.EXPOSED_DEFAULT_CREDS,
                    evidence=["admin/admin worked"]),
        ScanResult(target=Target(url="http://safe.ex.com"),
                    middleware="jenkins", auth_status=AuthStatus.PROTECTED,
                    evidence=["login required"]),
        ScanResult(target=Target(url="http://unknown.ex.com"),
                    auth_status=AuthStatus.UNKNOWN, evidence=["no fingerprint"]),
    ]


def test_terminal_summary_contains_counts(sample_results, capsys):
    render_terminal_summary(sample_results)
    out = capsys.readouterr().out
    assert "CRITICAL" in out
    assert "HIGH" in out
    assert "nacos" in out


def test_html_report_is_self_contained(sample_results):
    html = render_html(sample_results)
    assert "<html" in html.lower()
    assert "nacos.ex.com" in html
    assert "<style" in html  # inlined CSS for self-contained file


def test_markdown_report_has_table(sample_results):
    md = render_markdown(sample_results)
    assert "# Ingress Exposure Scan Report" in md
    assert "| Endpoint |" in md
    assert "nacos.ex.com" in md
