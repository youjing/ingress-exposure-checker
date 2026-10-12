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
        from iec.models import TestDetail
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
        detail = TestDetail(
            name="通用信号检测",
            description="未识别的服务,仅收集认证相关信号(HTTP Basic 挑战/登录页特征),不下结论",
            target=ctx.target.url,
            request=f"GET {ctx.target.url}",
            response="; ".join(evidence) if evidence else "未检测到认证相关信号",
            result=("启用 HTTP Basic 认证" if status == AuthStatus.BASIC_AUTH_PROTECTED
                    else "信号不足,无法判定鉴权状态"),
            vulnerable=False,
        )
        return AuthCheckResult(status=status,
                               evidence=evidence or ["no auth signal detected"],
                               details=[detail])
