from __future__ import annotations

from urllib.parse import urljoin

from iec.credcheck import check_default_creds
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class PhpMyAdminPlugin(MiddlewarePlugin):
    name = "phpmyadmin"
    description = "phpMyAdmin database console"
    default_creds = [("root", ""), ("root", "root")]

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if "phpmyadmin" in body or "pma_" in body:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        origin = urljoin(ctx.target.url.rstrip("/") + "/", "")
        login_path = urljoin(origin, "/index.php")
        return await check_default_creds(
            ctx, login_path=login_path,
            user_field="pma_username", password_field="password",
            creds=self.default_creds,
            success_markers=["server=", "token", "db_structure"],
            failure_markers=["access denied", "login_invalid", "invalid"])
