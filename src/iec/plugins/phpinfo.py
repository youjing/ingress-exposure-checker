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
        return AuthCheckResult(
            status=AuthStatus.EXPOSED_NO_AUTH,
            evidence=["phpinfo page is always an exposure"])
