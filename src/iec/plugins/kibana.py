from __future__ import annotations

import httpx
from urllib.parse import urljoin

from iec.credcheck import check_api_no_auth, _any_marker
from iec.models import AuthStatus, AuthCheckResult, FingerprintResult, TestDetail
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext

KIBANA_DEFAULT_CREDS = [
    ("elastic", "elastic"),
    ("elastic", "changeme"),
    ("kibana", "kibana"),
]


def _login_url(ctx: ProbeContext) -> str:
    """Kibana login API lives under the fingerprinted kibana base path."""
    base = ctx.target.url.rstrip("/")
    return f"{base}/internal/security/login"


async def _try_kibana_login(ctx: ProbeContext, user: str, password: str) -> tuple[bool, str]:
    """POST Kibana internal login API. Returns (success, response_summary)."""
    base = ctx.target.url.rstrip("/")
    payload = {
        "params": {"username": user, "password": password},
        "providerType": "basic",
        "providerName": "basic",
        "currentURL": f"{base}/login",
    }
    resp = await ctx.client.post(
        _login_url(ctx), json=payload,
        headers={"kbn-xsrf": "true"},
    )
    summary = f"HTTP {resp.status_code} - {resp.text.strip()[:120]}"
    # 成功: 200 + {"location": "..."}; 失败: 401 Unauthorized
    success = resp.status_code == 200 and '"location"' in resp.text
    return success, summary


@register
class KibanaPlugin(MiddlewarePlugin):
    name = "kibana"
    service_type = "web_ui"
    description = "Kibana UI (Elastic Stack)"
    default_creds = KIBANA_DEFAULT_CREDS

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        markers = ("kibana", "<title>elastic</title>", "kbn-")
        hits = sum(1 for m in markers if m in body)
        if hits >= 2 or "/login?next=" in body or "kibana" in body:
            return FingerprintResult(
                middleware=self.name,
                confidence="high" if hits >= 2 else "low",
                evidence=["body markers"] if hits >= 2 else ["weak body marker"],
            )
        return None

    async def check_auth(self, ctx: ProbeContext):
        details: list[TestDetail] = []

        # 1) API 未授权检查 (Kibana 健康接口)
        no_auth = await check_api_no_auth(
            ctx, probe_paths=["/api/status"],
            success_markers=["version", "metrics"])
        details.extend(no_auth.details)
        if no_auth.status == AuthStatus.EXPOSED_NO_AUTH:
            return no_auth

        # 2) 默认凭据测试 (Elasticsearch basic 认证经由 Kibana)
        #    控制组: 先用错误凭据确认失败特征可靠
        ctrl_url = _login_url(ctx)
        try:
            ok, ctrl_summary = await _try_kibana_login(ctx, "__invalid_user__", "__invalid_pass__")
            ctrl_ok = not ok
        except httpx.HTTPError as e:
            details.append(TestDetail(
                name="控制组测试",
                description="使用错误凭据验证登录失败特征是否可靠",
                target=ctrl_url, credentials="__invalid_user__/__invalid_pass__",
                request="POST /internal/security/login (json)",
                response=f"请求失败: {type(e).__name__}",
                result="无法判定", vulnerable=False,
            ))
            return AuthCheckResult(status=AuthStatus.INCONCLUSIVE,
                                   evidence=["control request failed"], details=details)

        details.append(TestDetail(
            name="控制组测试",
            description="使用错误凭据验证登录失败特征是否可靠",
            target=ctrl_url, credentials="__invalid_user__/__invalid_pass__",
            request="POST /internal/security/login (json)",
            response=ctrl_summary,
            result="失败特征确认" if ctrl_ok else "失败特征未出现",
            vulnerable=False,
        ))
        if not ctrl_ok:
            return AuthCheckResult(status=AuthStatus.INCONCLUSIVE,
                                   evidence=["control group did not fail as expected"],
                                   details=details)

        # 3) 逐组尝试默认凭据
        for user, passwd in KIBANA_DEFAULT_CREDS:
            cred_str = f"{user}/{passwd}"
            try:
                success, summary = await _try_kibana_login(ctx, user, passwd)
            except httpx.HTTPError as e:
                details.append(TestDetail(
                    name="默认凭据测试",
                    description=f"使用默认凭据 {cred_str} 尝试登录 Kibana",
                    target=ctrl_url, credentials=cred_str,
                    request="POST /internal/security/login (json)",
                    response=f"请求失败: {type(e).__name__}",
                    result="请求异常", vulnerable=False,
                ))
                continue
            details.append(TestDetail(
                name="默认凭据测试",
                description=f"使用默认凭据 {cred_str} 尝试登录 Kibana",
                target=ctrl_url, credentials=cred_str,
                request="POST /internal/security/login (json)",
                response=summary,
                result="登录成功(存在漏洞!)" if success else "登录被拒绝(已有保护)",
                vulnerable=success,
            ))
            if success:
                return AuthCheckResult(status=AuthStatus.EXPOSED_DEFAULT_CREDS,
                                       evidence=[f"kibana default creds worked: {cred_str}"],
                                       details=details)

        return AuthCheckResult(status=AuthStatus.PROTECTED,
                               evidence=["kibana default creds all failed"],
                               details=details)
