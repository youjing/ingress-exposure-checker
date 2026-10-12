from __future__ import annotations

from urllib.parse import urljoin

import httpx
from iec.models import AuthStatus, AuthCheckResult, TestDetail
from iec.probe import ProbeContext


def _abs_url(ctx: ProbeContext, path: str) -> str:
    """Build an absolute URL from a root-relative path on the target's origin.

    ``path`` is treated as root-relative (e.g. ``/login``) and joined against
    the target's origin (scheme + host + port), so a target URL that already
    contains a path does not double it.
    """
    origin = httpx.URL(ctx.target.url).copy_with(path="/")
    return urljoin(str(origin), path.lstrip("/"))


def _any_marker(text: str, markers: list[str]) -> bool:
    text_lower = text.lower()
    return any(m.lower() in text_lower for m in markers)


def _resp_summary(resp: httpx.Response, limit: int = 120) -> str:
    body = resp.text.strip().replace("\n", " ")
    if len(body) > limit:
        body = body[:limit] + "..."
    return f"HTTP {resp.status_code} - {body}" if body else f"HTTP {resp.status_code}"


async def check_default_creds(
    ctx: ProbeContext,
    *,
    login_path: str,
    user_field: str,
    password_field: str,
    creds: list[tuple[str, str]],
    success_markers: list[str],
    failure_markers: list[str],
) -> AuthCheckResult:
    """Form-login default-credential check with control group."""
    details: list[TestDetail] = []
    wrong_user, wrong_pass = "__invalid_user__", "__invalid_pass__"
    ctrl_url = _abs_url(ctx, login_path)

    # 控制组:用错误凭据验证失败特征可靠
    try:
        ctrl = await ctx.client.post(ctrl_url,
                                     data={user_field: wrong_user, password_field: wrong_pass})
        ctrl_summary = _resp_summary(ctrl)
        ctrl_failed = _any_marker(ctrl.text, failure_markers) or ctrl.status_code in (401, 403)
    except httpx.HTTPError as e:
        details.append(TestDetail(
            name="控制组测试",
            description="使用错误凭据验证登录失败特征是否可靠",
            target=str(ctrl_url), credentials=f"{wrong_user}/{wrong_pass}",
            request=f"POST {login_path} (form)", response=f"请求失败: {type(e).__name__}",
            result="无法判定", vulnerable=False,
        ))
        return AuthCheckResult(status=AuthStatus.INCONCLUSIVE,
                               evidence=["control request failed"], details=details)

    details.append(TestDetail(
        name="控制组测试",
        description="使用错误凭据验证登录失败特征是否可靠",
        target=str(ctrl_url), credentials=f"{wrong_user}/{wrong_pass}",
        request=f"POST {login_path} (form)", response=ctrl_summary,
        result="失败特征确认" if ctrl_failed else "失败特征未出现(可能不存在该登录接口)",
        vulnerable=False,
    ))

    if not ctrl_failed:
        return AuthCheckResult(status=AuthStatus.INCONCLUSIVE,
                               evidence=["control group did not exhibit expected failure marker"],
                               details=details)

    # 逐组尝试默认凭据
    for user, passwd in creds:
        cred_str = f"{user}/{passwd or '(空)'}"
        try:
            resp = await ctx.client.post(ctrl_url,
                                         data={user_field: user, password_field: passwd})
        except httpx.HTTPError as e:
            details.append(TestDetail(
                name="默认凭据测试",
                description=f"使用默认凭据 {cred_str} 尝试登录",
                target=str(ctrl_url), credentials=cred_str,
                request=f"POST {login_path} (form)", response=f"请求失败: {type(e).__name__}",
                result="请求异常", vulnerable=False,
            ))
            continue

        success = _any_marker(resp.text, success_markers) and resp.status_code in (200, 302)
        details.append(TestDetail(
            name="默认凭据测试",
            description=f"使用默认凭据 {cred_str} 尝试登录",
            target=str(ctrl_url), credentials=cred_str,
            request=f"POST {login_path} (form)", response=_resp_summary(resp),
            result="登录成功(存在漏洞!)" if success else "登录被拒绝(已有保护)",
            vulnerable=success,
        ))
        if success:
            return AuthCheckResult(status=AuthStatus.EXPOSED_DEFAULT_CREDS,
                                   evidence=[f"default creds worked: {user}"],
                                   details=details)

    return AuthCheckResult(status=AuthStatus.PROTECTED,
                           evidence=["default creds all failed"], details=details)


async def check_basic_auth(
    ctx: ProbeContext,
    *,
    probe_path: str,
    creds: list[tuple[str, str]],
) -> AuthCheckResult:
    """HTTP Basic Auth default-credential check."""
    details: list[TestDetail] = []
    probe_url = _abs_url(ctx, probe_path)

    for user, passwd in creds:
        cred_str = f"{user}/{passwd or '(空)'}"
        try:
            resp = await ctx.client.get(probe_url, auth=(user, passwd))
        except httpx.HTTPError as e:
            details.append(TestDetail(
                name="Basic 认证测试",
                description=f"使用 Basic 凭据 {cred_str} 访问受保护接口",
                target=str(probe_url), credentials=cred_str,
                request=f"GET {probe_path} (basic auth)", response=f"请求失败: {type(e).__name__}",
                result="请求异常", vulnerable=False,
            ))
            continue

        success = resp.status_code == 200
        details.append(TestDetail(
            name="Basic 认证测试",
            description=f"使用 Basic 凭据 {cred_str} 访问受保护接口",
            target=str(probe_url), credentials=cred_str,
            request=f"GET {probe_path} (basic auth)", response=_resp_summary(resp),
            result="认证通过(存在漏洞!)" if success else "认证被拒绝(已有保护)",
            vulnerable=success,
        ))
        if success:
            return AuthCheckResult(status=AuthStatus.EXPOSED_DEFAULT_CREDS,
                                   evidence=[f"basic auth worked: {user}"],
                                   details=details)

    return AuthCheckResult(status=AuthStatus.PROTECTED,
                           evidence=["basic auth creds all failed"], details=details)


async def check_api_no_auth(
    ctx: ProbeContext,
    *,
    probe_paths: list[str],
    success_markers: list[str],
) -> AuthCheckResult:
    """Probe API endpoints without credentials."""
    details: list[TestDetail] = []
    for path in probe_paths:
        probe_url = _abs_url(ctx, path)
        try:
            status, body, _ = await ctx.fetch_path(path)
        except Exception as e:
            details.append(TestDetail(
                name="未授权访问测试",
                description="不带任何凭据直接请求敏感 API,检查是否泄露数据",
                target=str(probe_url),
                request=f"GET {path} (无认证)", response=f"请求失败: {type(e).__name__}",
                result="请求异常", vulnerable=False,
            ))
            continue

        body_short = body.strip().replace("\n", " ")[:120]
        body_lower = body.lower()
        # An HTML page here is a gateway/SPA fallback, not a JSON API response
        is_html = "<html" in body_lower or "<!doctype" in body_lower
        exposed = status == 200 and _any_marker(body, success_markers) and not is_html
        protected = status in (401, 403)

        details.append(TestDetail(
            name="未授权访问测试",
            description="不带任何凭据直接请求敏感 API,检查是否泄露数据",
            target=str(probe_url),
            request=f"GET {path} (无认证)",
            response=f"HTTP {status} - {body_short}..." if len(body) > 120 else f"HTTP {status} - {body_short}",
            result="无需认证即可获取数据(存在漏洞!)" if exposed
                   else ("需要认证(已有保护)" if protected
                         else ("返回 HTML 页面而非 API 数据(网关回退页,不构成漏洞)" if is_html
                               else "响应无法判定")),
            vulnerable=exposed,
        ))

        if exposed:
            return AuthCheckResult(status=AuthStatus.EXPOSED_NO_AUTH,
                                   evidence=[f"unauthenticated access to {path}"],
                                   details=details)
        if protected:
            return AuthCheckResult(status=AuthStatus.PROTECTED,
                                   evidence=[f"{path} requires auth (status {status})"],
                                   details=details)

    return AuthCheckResult(status=AuthStatus.UNKNOWN,
                           evidence=["no probe path responded definitively"],
                           details=details)
