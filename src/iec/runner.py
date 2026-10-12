from __future__ import annotations

import asyncio
from typing import Callable

from iec.fingerprint import LOW, fingerprint
from iec.http import HttpClient
from iec.models import AuthStatus, ScanResult, Target, TestDetail
from iec.plugins import get_plugin
from iec.probe import build_context


async def scan_target(
    target: Target,
    *,
    concurrency: int = 20,
    timeout: float = 10.0,
    verify_tls: bool = True,
    on_found: Callable[[ScanResult], None] | None = None,
) -> ScanResult:
    result = ScanResult(target=target)
    try:
        async with HttpClient(
            concurrency=concurrency, per_host=2, timeout=timeout, verify_tls=verify_tls
        ) as client:
            ctx = await build_context(client, target)
            if "_error" in ctx.home_headers:
                result.auth_status = AuthStatus.UNREACHABLE
                result.error = ctx.home_headers["_error"]
                result.evidence.append("target unreachable during probe")
                result.details.append(TestDetail(
                    name="连通性测试",
                    description="请求目标首页,检查服务是否可达",
                    target=target.url,
                    request=f"GET {target.url}",
                    response=f"连接失败: {result.error}",
                    result="目标不可达,无法继续测试",
                    vulnerable=False,
                ))
                if on_found and result.auth_status in (
                    AuthStatus.EXPOSED_NO_AUTH,
                    AuthStatus.EXPOSED_DEFAULT_CREDS,
                ):
                    on_found(result)
                return result
            fp = await fingerprint(ctx)
            if fp is None:
                result.auth_status = AuthStatus.UNKNOWN
                result.evidence.append("no fingerprint match")
                result.details.append(TestDetail(
                    name="指纹识别",
                    description="根据页面内容/响应头/favicon 识别部署的中间件类型",
                    target=target.url,
                    request=f"GET {target.url}",
                    response=f"HTTP 页面特征无已知中间件匹配 (body {len(ctx.home_body)} 字节)",
                    result="无法识别服务类型,跳过针对性漏洞检测",
                    vulnerable=False,
                ))
            else:
                result.middleware = fp.middleware
                result.middleware_version = fp.version
                result.evidence.extend(fp.evidence)
                result.details.append(TestDetail(
                    name="指纹识别",
                    description="根据页面内容/响应头/favicon 识别部署的中间件类型",
                    target=target.url,
                    request=f"GET {target.url}",
                    response=f"匹配到 {fp.middleware} (置信度: {fp.confidence})",
                    result=f"识别为 {fp.middleware}",
                    vulnerable=False,
                ))
                plugin = get_plugin(fp.middleware)
                if plugin is None:
                    result.auth_status = AuthStatus.UNKNOWN
                    result.evidence.append("fingerprint matched but no plugin loaded")
                elif fp.confidence == LOW:
                    result.auth_status = AuthStatus.UNKNOWN
                    result.evidence.append(
                        "low-confidence fingerprint; auth check skipped to avoid false positives"
                    )
                    result.details.append(TestDetail(
                        name="置信度检查",
                        description="指纹置信度过低时跳过漏洞检测,避免误报",
                        target=target.url,
                        response=f"仅命中 1 个弱特征标记",
                        result="跳过漏洞检测(避免误报)",
                        vulnerable=False,
                    ))
                else:
                    check = await plugin.check_auth(ctx)
                    result.auth_status = check.status
                    result.evidence.extend(check.evidence)
                    result.details.extend(check.details)
    except Exception as e:
        result.auth_status = AuthStatus.ERROR
        result.error = f"{type(e).__name__}: {e}"
        result.details.append(TestDetail(
            name="扫描异常",
            description="扫描过程中发生未预期的异常",
            target=target.url,
            response=f"{type(e).__name__}: {e}",
            result="扫描失败",
            vulnerable=False,
        ))
    if on_found and result.auth_status in (
        AuthStatus.EXPOSED_NO_AUTH,
        AuthStatus.EXPOSED_DEFAULT_CREDS,
    ):
        on_found(result)
    return result


async def scan_all(
    targets: list[Target],
    *,
    concurrency: int = 20,
    timeout: float = 10.0,
    verify_tls: bool = True,
    on_found: Callable[[ScanResult], None] | None = None,
) -> list[ScanResult]:
    sem = asyncio.Semaphore(concurrency)

    async def _one(t: Target) -> ScanResult:
        async with sem:
            return await scan_target(
                t,
                concurrency=concurrency,
                timeout=timeout,
                verify_tls=verify_tls,
                on_found=on_found,
            )

    return await asyncio.gather(*(_one(t) for t in targets))
