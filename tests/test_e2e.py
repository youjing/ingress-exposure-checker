import httpx
import respx
import pytest
from iec.cli import main
from iec.plugins.base import PLUGINS, MiddlewarePlugin
from iec.models import FingerprintResult, AuthCheckResult, AuthStatus, Target


class MockGrafana(MiddlewarePlugin):
    name = "grafana"

    async def fingerprint(self, ctx):
        if "grafana" in (ctx.home_body or "").lower():
            return FingerprintResult(
                middleware="grafana", confidence="high", evidence=["body"]
            )
        return None

    async def check_auth(self, ctx):
        return AuthCheckResult(
            status=AuthStatus.EXPOSED_DEFAULT_CREDS, evidence=["mock default creds"]
        )


def test_e2e_generates_reports(tmp_path):
    snapshot = list(PLUGINS)
    # Ensure no real "grafana" plugin is loaded (e.g. from test_plugins.py imports),
    # so the mock is the only one driving the "grafana" fingerprint + auth check.
    PLUGINS[:] = [p for p in PLUGINS if p.name != "grafana"]
    PLUGINS.append(MockGrafana())
    try:
        input_file = tmp_path / "targets.txt"
        input_file.write_text(
            "http://grafana.ex.com/\nhttp://plain.ex.com/\n", encoding="utf-8"
        )
        html_out = tmp_path / "out.html"
        md_out = tmp_path / "out.md"
        with respx.mock:
            respx.get("http://grafana.ex.com/").mock(
                return_value=httpx.Response(200, text="grafana")
            )
            respx.get("http://grafana.ex.com/favicon.ico").mock(
                return_value=httpx.Response(404)
            )
            respx.get("http://plain.ex.com/").mock(
                return_value=httpx.Response(200, text="hello")
            )
            respx.get("http://plain.ex.com/favicon.ico").mock(
                return_value=httpx.Response(404)
            )
            from unittest.mock import patch

            with patch(
                "sys.argv",
                [
                    "iec",
                    str(input_file),
                    "--authorized",
                    "--output-html",
                    str(html_out),
                    "--output-md",
                    str(md_out),
                ],
            ):
                with pytest.raises(SystemExit) as exc:
                    main()
                assert exc.value.code == 1  # HIGH present (default creds)
        assert html_out.exists() and "grafana" in html_out.read_text(encoding="utf-8")
        assert md_out.exists() and "grafana" in md_out.read_text(encoding="utf-8")
    finally:
        PLUGINS[:] = snapshot
