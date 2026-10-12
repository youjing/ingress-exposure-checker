from __future__ import annotations

from urllib.parse import urljoin

import httpx
from iec.models import AuthStatus, AuthCheckResult
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
    wrong_user, wrong_pass = "__invalid_user__", "__invalid_pass__"
    try:
        ctrl = await ctx.client.post(_abs_url(ctx, login_path),
                                     data={user_field: wrong_user, password_field: wrong_pass})
        ctrl_failed = _any_marker(ctrl.text, failure_markers) or ctrl.status_code in (401, 403)
    except httpx.HTTPError:
        return AuthCheckResult(status=AuthStatus.INCONCLUSIVE, evidence=["control request failed"])

    if not ctrl_failed:
        return AuthCheckResult(status=AuthStatus.INCONCLUSIVE,
                               evidence=["control group did not exhibit expected failure marker"])

    for user, passwd in creds:
        try:
            resp = await ctx.client.post(_abs_url(ctx, login_path),
                                         data={user_field: user, password_field: passwd})
        except httpx.HTTPError:
            continue
        if _any_marker(resp.text, success_markers) and resp.status_code in (200, 302):
            return AuthCheckResult(status=AuthStatus.EXPOSED_DEFAULT_CREDS,
                                   evidence=[f"default creds worked: {user}"])

    return AuthCheckResult(status=AuthStatus.PROTECTED, evidence=["default creds all failed"])


async def check_basic_auth(
    ctx: ProbeContext,
    *,
    probe_path: str,
    creds: list[tuple[str, str]],
) -> AuthCheckResult:
    """HTTP Basic Auth default-credential check."""
    for user, passwd in creds:
        try:
            resp = await ctx.client.get(_abs_url(ctx, probe_path), auth=(user, passwd))
        except httpx.HTTPError:
            continue
        if resp.status_code == 200:
            return AuthCheckResult(status=AuthStatus.EXPOSED_DEFAULT_CREDS,
                                   evidence=[f"basic auth worked: {user}"])
    return AuthCheckResult(status=AuthStatus.PROTECTED, evidence=["basic auth creds all failed"])


async def check_api_no_auth(
    ctx: ProbeContext,
    *,
    probe_paths: list[str],
    success_markers: list[str],
) -> AuthCheckResult:
    """Probe API endpoints without credentials."""
    for path in probe_paths:
        try:
            status, body, _ = await ctx.fetch_path(path)
        except Exception:
            continue
        if status == 200 and _any_marker(body, success_markers):
            return AuthCheckResult(status=AuthStatus.EXPOSED_NO_AUTH,
                                   evidence=[f"unauthenticated access to {path}"])
        if status in (401, 403):
            return AuthCheckResult(status=AuthStatus.PROTECTED,
                                   evidence=[f"{path} requires auth (status {status})"])
    return AuthCheckResult(status=AuthStatus.UNKNOWN, evidence=["no probe path responded definitively"])
