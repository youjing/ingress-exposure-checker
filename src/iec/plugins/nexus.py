from __future__ import annotations

import httpx
from urllib.parse import urljoin, urlparse

from iec.credcheck import check_basic_auth
from iec.models import AuthStatus, AuthCheckResult, FingerprintResult, TestDetail
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


def _origin_url(ctx: ProbeContext, path: str) -> str:
    """Nexus REST API 与仓库路径均挂在 origin 根下。"""
    origin = urlparse(ctx.target.url)._replace(path="", query="", fragment="").geturl()
    return f"{origin}/{path.lstrip('/')}"


def _is_json(body: str) -> bool:
    b = body.strip()
    return b.startswith("{") or b.startswith("[")


async def _list_repositories(ctx: ProbeContext) -> list[dict] | None:
    """匿名获取仓库列表。None = 匿名被拒(401/403/异常)。"""
    try:
        resp = await ctx.client.get(_origin_url(ctx, "/service/rest/v1/repositories"))
    except httpx.HTTPError:
        return None
    if resp.status_code != 200 or not _is_json(resp.text):
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    return data if isinstance(data, list) else None


async def _search_artifacts(ctx: ProbeContext, repository: str) -> list[dict]:
    """匿名搜索指定仓库的制品,返回含 downloadUrl 的条目。"""
    try:
        resp = await ctx.client.get(
            _origin_url(ctx, "/service/rest/v1/search"),
            params={"repository": repository},
        )
    except httpx.HTTPError:
        return []
    if resp.status_code != 200 or not _is_json(resp.text):
        return []
    try:
        return resp.json().get("items", []) or []
    except ValueError:
        return []


async def _download_anonymous(ctx: ProbeContext, download_url: str) -> tuple[bool, str]:
    """下载制品验证。search 返回的 downloadUrl 指向服务端自配地址
    (可能是内网端口), 需改写到目标 origin 再验证。"""
    path = urlparse(download_url).path
    url = _origin_url(ctx, path)
    try:
        resp = await ctx.client.get(url)
    except httpx.HTTPError as e:
        return False, f"下载请求失败: {type(e).__name__}"
    if resp.status_code == 200 and len(resp.content) > 0:
        ctype = resp.headers.get("content-type", "unknown").split(";")[0]
        return True, f"HTTP 200 - {len(resp.content)} 字节 ({ctype})"
    return False, f"HTTP {resp.status_code}"


@register
class NexusPlugin(MiddlewarePlugin):
    name = "nexus"
    description = "Sonatype Nexus repository"
    default_creds = [("admin", "admin123")]

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if "nexus" in body or "sonatype" in body:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        details: list[TestDetail] = []

        # 1) 匿名仓库列表: 空列表 = 匿名无任何仓库权限(不算发现)
        repos = await _list_repositories(ctx)
        if repos:  # 非空列表才可能构成暴露
            names = [r.get("name", "?") for r in repos]
            hosted = [r.get("name", "?") for r in repos if r.get("type") == "hosted"]
            details.append(TestDetail(
                name="匿名仓库列表测试",
                description="不带凭据请求 Nexus REST API,检查匿名用户是否可浏览仓库",
                target=_origin_url(ctx, "/service/rest/v1/repositories"),
                request="GET /service/rest/v1/repositories (无认证)",
                response=f"HTTP 200 - 返回 {len(names)} 个仓库: {', '.join(names[:8])}"
                         + ("..." if len(names) > 8 else ""),
                result=f"匿名可列出仓库列表(存在漏洞!) 私有/托管仓库: {', '.join(hosted) or '无'}",
                vulnerable=True,
            ))

            # 2) 匿名搜索内部制品 (优先 hosted 仓库 = 公司内部制品)
            candidates = (hosted + ["maven-public"])[:3]
            evidence_parts: list[str] = []
            for repo in candidates:
                items = await _search_artifacts(ctx, repo)
                if not items:
                    continue
                sample = items[0]
                dl_url = ""
                for a in sample.get("assets", []):
                    dl_url = a.get("downloadUrl", "")
                    break
                details.append(TestDetail(
                    name="匿名制品搜索测试",
                    description=f"匿名调用搜索 API,检查是否可枚举仓库内容(仓库: {repo})",
                    target=_origin_url(ctx, "/service/rest/v1/search"),
                    credentials="-",
                    request=f"GET /service/rest/v1/search?repository={repo} (无认证)",
                    response=f"HTTP 200 - 命中制品示例: {sample.get('name', '?')} "
                             f"{sample.get('version', '')}",
                    result=f"匿名可搜索/枚举制品清单(存在漏洞!)",
                    vulnerable=True,
                ))
                if dl_url:
                    ok, summary = await _download_anonymous(ctx, dl_url)
                    details.append(TestDetail(
                        name="匿名制品下载测试",
                        description="实际下载一个制品文件,确认匿名用户可获取 jar 包内容",
                        target=_origin_url(ctx, urlparse(dl_url).path),
                        credentials="-",
                        request=f"GET {urlparse(dl_url).path} (无认证)",
                        response=summary,
                        result=("匿名下载成功,内部制品可被公网任何人获取(存在漏洞!)"
                                if ok else "下载未成功,但仓库列表/搜索已匿名可见"),
                        vulnerable=ok,
                    ))
                    if ok:
                        evidence_parts.append(
                            f"anonymous download ok: {urlparse(dl_url).path}")
                break  # 一个仓库有结果即可

            evidence = [f"nexus anonymous access enabled; repos: {', '.join(names[:5])}"]
            evidence.extend(evidence_parts)
            if evidence_parts:
                # 实际下载验证成功 → 严重
                return AuthCheckResult(status=AuthStatus.EXPOSED_NO_AUTH,
                                       evidence=evidence, details=details)
            # 仓库列表可见但制品下载未验证成功 → 不定级, 待人工确认
            return AuthCheckResult(status=AuthStatus.INCONCLUSIVE,
                                   evidence=evidence, details=details)

        # 3) 匿名关闭或匿名无任何可见仓库 → 默认凭据测试 (admin/admin123)
        origin_probe = _origin_url(ctx, "/service/rest/v1/status")
        if repos is None:
            details.append(TestDetail(
                name="匿名仓库列表测试",
                description="不带凭据请求 Nexus REST API,检查匿名用户是否可浏览仓库",
                target=origin_probe,
                request="GET /service/rest/v1/repositories (无认证)",
                response="HTTP 401/403 或请求失败",
                result="匿名访问已关闭(已有保护)",
                vulnerable=False,
            ))
        else:  # repos == [] : 匿名配置开启但无任何可见仓库
            details.append(TestDetail(
                name="匿名仓库列表测试",
                description="不带凭据请求 Nexus REST API,检查匿名用户是否可浏览仓库",
                target=_origin_url(ctx, "/service/rest/v1/repositories"),
                request="GET /service/rest/v1/repositories (无认证)",
                response="HTTP 200 - 返回空列表 (匿名角色无任何仓库查看权限)",
                result="匿名无法访问任何仓库(已有保护)",
                vulnerable=False,
            ))
        creds_result = await check_basic_auth(ctx, probe_path="/service/rest/v1/status",
                                              creds=self.default_creds)
        details.extend(creds_result.details)
        return AuthCheckResult(status=creds_result.status,
                               evidence=creds_result.evidence,
                               details=details)
