from __future__ import annotations

import httpx

from iec.models import AuthStatus, AuthCheckResult, FingerprintResult, TestDetail
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext

# OpenAPI/Swagger 规范 JSON 的常见路径(相对目标 URL)
OPENAPI_SPEC_PATHS = [
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/swagger.json",
    "/v2/swagger.json",
    "/openapi.json",
    "/v3/api-docs/swagger.json",
]

# Swagger UI 页面的常见路径
SWAGGER_UI_PATHS = [
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger-ui/",
    "/swagger/",
    "/docs",
]

# Spring Boot Actuator 常见端点
ACTUATOR_PATHS = [
    "/actuator",
    "/actuator/env",
    "/actuator/heapdump",
    "/actuator/health",
    "/actuator/mappings",
    "/actuator/configprops",
]

# Actuator 中泄露级别最高的端点
ACTUATOR_SENSITIVE = {
    "/actuator/env": "环境变量(常含数据库密码、密钥)",
    "/actuator/heapdump": "JVM 内存转储(可提取凭据)",
    "/actuator/configprops": "应用配置(含敏感项)",
    "/actuator/mappings": "全部 URL 映射",
}


def _is_json(body: str) -> bool:
    b = body.strip().lower()
    return b.startswith("{") or b.startswith("[")


def _is_html(body: str) -> bool:
    b = body.lower()
    return "<html" in b or "<!doctype" in b


async def _fetch(ctx: ProbeContext, path: str) -> tuple[int, str, dict[str, str]]:
    return await ctx.fetch_path(path)


async def find_openapi_spec(ctx: ProbeContext) -> tuple[str | None, str]:
    """Probe common OpenAPI/Swagger spec paths.

    Returns (spec_path, summary) or (None, "").
    """
    for path in OPENAPI_SPEC_PATHS:
        try:
            status, body, _ = await _fetch(ctx, path)
        except httpx.HTTPError:
            continue
        if status != 200 or _is_html(body):
            continue
        bl = body.lower()
        if ('"openapi"' in bl or '"swagger"' in bl or '"swaggerversion"' in bl
                or '"paths"' in bl) and _is_json(body):
            return path, f"HTTP {status} - {body.strip()[:100]}"
    return None, ""


async def find_swagger_ui(ctx: ProbeContext) -> tuple[str | None, str]:
    """Probe common Swagger UI page paths."""
    for path in SWAGGER_UI_PATHS:
        try:
            status, body, _ = await _fetch(ctx, path)
        except httpx.HTTPError:
            continue
        if status != 200 or not _is_html(body):
            continue
        bl = body.lower()
        if "<title>swagger ui" in bl or "swagger-ui" in bl.replace("_", "-"):
            return path, f"HTTP {status} - Swagger UI 页面"
    return None, ""


async def find_actuator(ctx: ProbeContext) -> tuple[str | None, list[str], str]:
    """Probe Spring Boot Actuator endpoints.

    Returns (base_path_or_None, [sensitive_paths_ok], summary).
    """
    # 先探测 base
    base_ok = False
    summary = ""
    try:
        status, body, _ = await _fetch(ctx, "/actuator")
        if status == 200 and _is_json(body) and '"_links"' in body.lower():
            base_ok = True
            summary = f"HTTP {status} - {body.strip()[:100]}"
    except httpx.HTTPError:
        pass

    # 再探测各敏感端点(base 不通时子端点仍可能暴露)
    sensitive_hits: list[str] = []
    for path in ACTUATOR_SENSITIVE:
        try:
            status, body, headers = await _fetch(ctx, path)
        except httpx.HTTPError:
            continue
        if status != 200:
            continue
        ctype = headers.get("content-type", "").lower()
        bl = body.lower()
        if path == "/actuator/heapdump":
            # 二进制转储: 无 HTML、200 即视为暴露
            if not _is_html(body):
                sensitive_hits.append(path)
        elif _is_json(body) and (
                '"propertysources"' in bl or '"activeprofiles"' in bl
                or '"status"' in bl or '"contexts"' in bl or '"_links"' in bl):
            sensitive_hits.append(path)

    if base_ok or sensitive_hits:
        if not summary:
            summary = f"HTTP 200 - {sensitive_hits[0]}" if sensitive_hits else "HTTP 200"
        return ("/actuator", sensitive_hits, summary)
    return None, [], ""


@register
class SwaggerPlugin(MiddlewarePlugin):
    name = "swagger"
    service_type = "api"
    description = "Swagger UI / OpenAPI 文档"

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if "<title>swagger ui" in body or ('swagger-ui' in body and _is_html(body)):
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["swagger ui page"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        details: list[TestDetail] = []
        spec_path, summary = await find_openapi_spec(ctx)
        if spec_path:
            details.append(TestDetail(
                name="API 文档暴露测试",
                description="探测常见 OpenAPI/Swagger 规范路径,检查 API 文档是否公开",
                target=ctx.target.url + spec_path,
                request=f"GET {spec_path} (无认证)",
                response=summary,
                result="API 规范文档无需认证即可获取(存在漏洞!)",
                vulnerable=True,
            ))
            return AuthCheckResult(
                status=AuthStatus.EXPOSED_NO_AUTH,
                evidence=[f"openapi spec exposed at {spec_path}"],
                details=details)

        ui_path, ui_summary = await find_swagger_ui(ctx)
        if ui_path:
            details.append(TestDetail(
                name="API 文档暴露测试",
                description="探测常见 Swagger UI 页面路径,检查交互式 API 文档是否公开",
                target=ctx.target.url + ui_path,
                request=f"GET {ui_path} (无认证)",
                response=ui_summary,
                result="Swagger UI 无需认证即可访问(存在漏洞!)",
                vulnerable=True,
            ))
            return AuthCheckResult(
                status=AuthStatus.EXPOSED_NO_AUTH,
                evidence=[f"swagger ui exposed at {ui_path}"],
                details=details)

        return AuthCheckResult(status=AuthStatus.PROTECTED,
                               evidence=["no swagger/openapi endpoints found"],
                               details=details)


@register
class ActuatorPlugin(MiddlewarePlugin):
    name = "actuator"
    service_type = "api"
    description = "Spring Boot Actuator 管理端点"

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if _is_json(body) and '"_links"' in body and '"self"' in body and "actuator" in body:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["actuator _links json"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        base, sensitive_hits, summary = await find_actuator(ctx)
        details: list[TestDetail] = []
        if not base:
            return AuthCheckResult(status=AuthStatus.PROTECTED,
                                   evidence=["no actuator endpoints found"],
                                   details=details)

        sensitive_zh = "、".join(f"{p} ({ACTUATOR_SENSITIVE[p]})" for p in sensitive_hits) or "无"
        details.append(TestDetail(
            name="Actuator 暴露测试",
            description="探测 Spring Boot Actuator 管理端点,检查运维接口是否公开",
            target=ctx.target.url + "/actuator",
            request="GET /actuator, /actuator/env, /actuator/heapdump 等 (无认证)",
            response=summary,
            result=f"Actuator 无需认证即可访问(存在漏洞!) 敏感端点: {sensitive_zh}",
            vulnerable=True,
        ))
        return AuthCheckResult(
            status=AuthStatus.EXPOSED_NO_AUTH,
            evidence=[f"actuator exposed; sensitive: {', '.join(sensitive_hits) or 'base only'}"],
            details=details)


async def probe_api_docs(ctx: ProbeContext) -> tuple[str | None, AuthCheckResult]:
    """Universal API-doc exposure probe for targets without a fingerprint match.

    Returns (middleware_name | None, AuthCheckResult).
    """
    result = await SwaggerPlugin().check_auth(ctx)
    if result.status == AuthStatus.EXPOSED_NO_AUTH:
        return "swagger", result
    result = await ActuatorPlugin().check_auth(ctx)
    if result.status == AuthStatus.EXPOSED_NO_AUTH:
        return "actuator", result
    return None, AuthCheckResult(status=AuthStatus.UNKNOWN,
                                 evidence=["no api-doc exposure found"])
