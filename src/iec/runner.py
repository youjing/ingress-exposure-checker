from __future__ import annotations

import asyncio
from typing import Callable

from iec.fingerprint import LOW, fingerprint
from iec.http import HttpClient
from iec.models import AuthStatus, ScanResult, Target
from iec.plugins.base import get_plugin
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
            else:
                result.middleware = fp.middleware
                result.middleware_version = fp.version
                result.evidence.extend(fp.evidence)
                plugin = get_plugin(fp.middleware)
                if plugin is None:
                    result.auth_status = AuthStatus.UNKNOWN
                    result.evidence.append("fingerprint matched but no plugin loaded")
                elif fp.confidence == LOW:
                    result.auth_status = AuthStatus.UNKNOWN
                    result.evidence.append(
                        "low-confidence fingerprint; auth check skipped to avoid false positives"
                    )
                else:
                    check = await plugin.check_auth(ctx)
                    result.auth_status = check.status
                    result.evidence.extend(check.evidence)
    except Exception as e:
        result.auth_status = AuthStatus.ERROR
        result.error = f"{type(e).__name__}: {e}"
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
