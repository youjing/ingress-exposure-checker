from __future__ import annotations

from iec.models import AuthCheckResult, AuthStatus, FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class UnknownPlugin(MiddlewarePlugin):
    name = "unknown"
    description = "Generic fallback"

    async def fingerprint(self, ctx: ProbeContext):
        return None  # unknown is the absence of a match

    async def check_auth(self, ctx: ProbeContext):
        body = (ctx.home_body or "").lower()
        headers = {k.lower(): v.lower() for k, v in ctx.home_headers.items()}
        evidence = []
        if headers.get("www-authenticate", "").startswith("basic"):
            evidence.append("HTTP Basic Auth challenge present")
        if "login" in body or "sign in" in body:
            evidence.append("login page detected")
        status = (AuthStatus.BASIC_AUTH_PROTECTED
                  if evidence and "Basic Auth" in str(evidence)
                  else AuthStatus.UNKNOWN)
        return AuthCheckResult(status=status,
                               evidence=evidence or ["no auth signal detected"])
