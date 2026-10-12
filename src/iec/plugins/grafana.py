from __future__ import annotations

from urllib.parse import urljoin

from iec.credcheck import check_default_creds
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class GrafanaPlugin(MiddlewarePlugin):
    name = "grafana"
    description = "Grafana dashboard"
    default_creds = [("admin", "admin")]

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        # Grafana login page markers (including SSO/Keycloak-proxied login pages)
        markers = (
            "grafana", 'id="grafana"', "grafana-app", "login-pf",
            "grafana-login", "__grafana", "public/app",
        )
        hits = sum(1 for m in markers if m in body)
        # Grafana often redirects to SSO (Keycloak) login which still references grafana
        if hits >= 2 or "<title>grafana</title>" in body:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=[f"{hits} body markers"])
        if hits == 1:
            return FingerprintResult(middleware=self.name, confidence="low",
                                     evidence=["weak body marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        from iec.models import AuthCheckResult, AuthStatus

        body = (ctx.home_body or "").lower()
        # Grafana behind SSO (Keycloak/OAuth): login is delegated, no local default creds
        sso_markers = ("keycloak", "openid-connect", "oauth", "realms/",
                       "auth/realms", "protocol/openid")
        if any(m in body for m in sso_markers):
            return AuthCheckResult(
                status=AuthStatus.PROTECTED,
                evidence=["grafana auth delegated to SSO (Keycloak/OAuth); no local default creds to test"],
            )

        login_path = urljoin(ctx.target.url.rstrip("/") + "/", "login")
        return await check_default_creds(
            ctx, login_path=login_path,
            user_field="user", password_field="password",
            creds=self.default_creds,
            success_markers=["redirect to /", '"loggedIn":true', "grafana-user"],
            failure_markers=["invalid username", "invalid password",
                             "does not exist", "invalid"],
        )
