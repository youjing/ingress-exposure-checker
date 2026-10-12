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
        from iec.models import TestDetail
        origin = urljoin(ctx.target.url.rstrip("/") + "/", "")
        probe_paths = [urljoin(origin, "/manage"), urljoin(origin, "/script")]
        no_auth = await check_api_no_auth(
            ctx, probe_paths=probe_paths,
            success_markers=["jenkins", "Dashboard"])
        if no_auth.status == AuthStatus.EXPOSED_NO_AUTH:
            return no_auth
        return AuthCheckResult(status=AuthStatus.PROTECTED,
                               evidence=["login required"],
                               details=[TestDetail(
                                   name="未授权访问测试",
                                   description="直接访问 Jenkins 管理面板/脚本控制台,检查是否需要登录",
                                   target=ctx.target.url,
                                   request="GET /manage, /script (无认证)",
                                   response="访问被重定向到登录页",
                                   result="需要登录(已有保护)",
                                   vulnerable=False,
                               )])
