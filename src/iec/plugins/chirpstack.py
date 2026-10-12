from __future__ import annotations

import httpx

from iec.models import AuthStatus, AuthCheckResult, FingerprintResult, TestDetail
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext

CHIRPSTACK_DEFAULT_CREDS = [("admin", "admin")]


def _login_endpoints(ctx: ProbeContext) -> list[tuple[str, str]]:
    """ChirpStack login endpoints: v3 (/api/internal/login) and v4 (/api/login)."""
    base = ctx.target.url.rstrip("/")
    return [
        (f"{base}/api/internal/login", "v3"),
        (f"{base}/api/login", "v4"),
    ]


async def _try_login(ctx: ProbeContext, url: str, user: str, password: str) -> tuple[bool, str]:
    """POST ChirpStack login API. Returns (success, response_summary)."""
    resp = await ctx.client.post(url, json={"email": user, "password": password})
    summary = f"HTTP {resp.status_code} - {resp.text.strip()[:120]}"
    # 成功: 200 + jwt (v3) 或 token (v4); 失败: 401 invalid username or password
    success = resp.status_code == 200 and ('"jwt"' in resp.text or '"token"' in resp.text)
    return success, summary


@register
class ChirpStackPlugin(MiddlewarePlugin):
    name = "chirpstack"
    service_type = "web_ui"
    description = "ChirpStack LoRaWAN network server"
    default_creds = CHIRPSTACK_DEFAULT_CREDS

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if "chirpstack" in body:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body/title marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        details: list[TestDetail] = []
        endpoints = _login_endpoints(ctx)

        # 找到可用的登录端点 (控制组请求 404 = 端点不存在)
        login_url, api_version = None, None
        ctrl_summary = ""
        for url, ver in endpoints:
            try:
                ok, ctrl_summary = await _try_login(
                    ctx, url, "__invalid_user__", "__invalid_pass__")
            except httpx.HTTPError as e:
                details.append(TestDetail(
                    name="控制组测试",
                    description=f"使用错误凭据验证登录失败特征是否可靠 ({ver} API)",
                    target=url, credentials="__invalid_user__/__invalid_pass__",
                    request=f"POST {url.split(ctx.target.url)[1]} (json)",
                    response=f"请求失败: {type(e).__name__}",
                    result="请求异常", vulnerable=False,
                ))
                continue
            if "404" in ctrl_summary.split(" - ")[0]:
                continue  # 该版本端点不存在,尝试下一个
            login_url, api_version = url, ver
            break

        if login_url is None:
            return AuthCheckResult(status=AuthStatus.INCONCLUSIVE,
                                   evidence=["no chirpstack login endpoint responded"],
                                   details=details)

        details.append(TestDetail(
            name="控制组测试",
            description=f"使用错误凭据验证登录失败特征是否可靠 (ChirpStack {api_version} API)",
            target=login_url, credentials="__invalid_user__/__invalid_pass__",
            request=f"POST {login_url.split(ctx.target.url)[1]} (json)",
            response=ctrl_summary,
            result="失败特征确认" if "401" in ctrl_summary else "失败特征未出现",
            vulnerable=False,
        ))
        if "401" not in ctrl_summary:
            return AuthCheckResult(status=AuthStatus.INCONCLUSIVE,
                                   evidence=["control group did not fail as expected"],
                                   details=details)

        # 逐组尝试默认凭据
        for user, passwd in CHIRPSTACK_DEFAULT_CREDS:
            cred_str = f"{user}/{passwd}"
            try:
                success, summary = await _try_login(ctx, login_url, user, passwd)
            except httpx.HTTPError as e:
                details.append(TestDetail(
                    name="默认凭据测试",
                    description=f"使用默认凭据 {cred_str} 尝试登录 ChirpStack ({api_version} API)",
                    target=login_url, credentials=cred_str,
                    request=f"POST {login_url.split(ctx.target.url)[1]} (json)",
                    response=f"请求失败: {type(e).__name__}",
                    result="请求异常", vulnerable=False,
                ))
                continue
            details.append(TestDetail(
                name="默认凭据测试",
                description=f"使用默认凭据 {cred_str} 尝试登录 ChirpStack ({api_version} API)",
                target=login_url, credentials=cred_str,
                request=f"POST {login_url.split(ctx.target.url)[1]} (json)",
                response=summary,
                result="登录成功,获取管理员会话(存在漏洞!)" if success else "登录被拒绝(已有保护)",
                vulnerable=success,
            ))
            if success:
                return AuthCheckResult(status=AuthStatus.EXPOSED_DEFAULT_CREDS,
                                       evidence=[f"chirpstack default creds worked: {cred_str} (admin JWT)"],
                                       details=details)

        return AuthCheckResult(status=AuthStatus.PROTECTED,
                               evidence=["chirpstack default creds all failed"],
                               details=details)
