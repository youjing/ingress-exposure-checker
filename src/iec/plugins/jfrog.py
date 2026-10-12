from __future__ import annotations

from urllib.parse import urljoin

from iec.credcheck import check_default_creds
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class JfrogPlugin(MiddlewarePlugin):
    name = "jfrog"
    description = "JFrog Artifactory"
    default_creds = [("admin", "password")]

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if "jfrog" in body or "artifactory" in body:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        origin = urljoin(ctx.target.url.rstrip("/") + "/", "")
        login_path = urljoin(origin, "/ui/login")
        return await check_default_creds(
            ctx, login_path=login_path,
            user_field="user", password_field="password",
            creds=self.default_creds,
            success_markers=["redirect", "dashboard"],
            failure_markers=["invalid", "incorrect"])
