from __future__ import annotations

from urllib.parse import urljoin

from iec.credcheck import check_api_no_auth
from iec.models import AuthStatus, FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class JenkinsPlugin(MiddlewarePlugin):
    name = "jenkins"
    service_type = "web_ui"
    description = "Jenkins automation server"

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if "jenkins" in body:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        origin = urljoin(ctx.target.url.rstrip("/") + "/", "")
        probe_paths = [urljoin(origin, "/manage"), urljoin(origin, "/script")]
        no_auth = await check_api_no_auth(
            ctx, probe_paths=probe_paths,
            success_markers=["jenkins", "Dashboard"])
        if no_auth.status == AuthStatus.EXPOSED_NO_AUTH:
            return no_auth
        return AuthCheckResult(status=AuthStatus.PROTECTED,
                               evidence=["login required"])
