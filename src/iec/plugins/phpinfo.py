from __future__ import annotations

from iec.models import AuthCheckResult, AuthStatus, FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class PhpInfoPlugin(MiddlewarePlugin):
    name = "phpinfo"
    description = "PHP info page (always an exposure)"

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if ("<title>phpinfo()</title>" in body or "php version" in body
                or "phpinfo(" in body):
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        from iec.models import TestDetail
        return AuthCheckResult(
            status=AuthStatus.EXPOSED_NO_AUTH,
            evidence=["phpinfo page is always an exposure"],
            details=[TestDetail(
                name="phpinfo 暴露检测",
                description="phpinfo 页面会泄露 PHP 版本、扩展、环境变量、路径等敏感配置",
                target=ctx.target.url,
                request=f"GET {ctx.target.url}",
                response="页面包含 phpinfo 特征",
                result="phpinfo 页面对公网暴露(存在漏洞!)",
                vulnerable=True,
            )],
        )
