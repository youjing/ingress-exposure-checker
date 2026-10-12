from __future__ import annotations

from urllib.parse import urljoin

from iec.credcheck import check_api_no_auth, check_default_creds
from iec.models import AuthStatus, FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class NacosPlugin(MiddlewarePlugin):
    name = "nacos"
    description = "Nacos config/registration console"
    default_creds = [("nacos", "nacos")]

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        markers = ("/nacos/", "nacos", "nacos console")
        hits = sum(1 for m in markers if m in body)
        if hits >= 2 or "/nacos/" in body:
            return FingerprintResult(
                middleware=self.name,
                confidence="high" if hits >= 2 else "low",
                evidence=["path/body markers"],
            )
        return None

    async def check_auth(self, ctx: ProbeContext):
        # Nacos without auth: API returns data directly
        api_path = urljoin(ctx.target.url.rstrip("/") + "/",
                           "nacos/v1/auth/users?pageNo=1&pageSize=1")
        no_auth = await check_api_no_auth(
            ctx, probe_paths=[api_path],
            success_markers=["totalCount", "pageItems"])
        if no_auth.status == AuthStatus.EXPOSED_NO_AUTH:
            return no_auth
        login_path = urljoin(ctx.target.url.rstrip("/") + "/",
                             "nacos/v1/auth/login")
        return await check_default_creds(
            ctx, login_path=login_path,
            user_field="username", password_field="password",
            creds=self.default_creds,
            success_markers=["accessToken", "nacos"],
            failure_markers=["invalid", "error", "user not found"],
        )
