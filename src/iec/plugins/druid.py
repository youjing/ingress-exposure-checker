from __future__ import annotations

from urllib.parse import urljoin, urlparse

from iec.credcheck import check_api_no_auth
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class DruidPlugin(MiddlewarePlugin):
    name = "druid"
    description = "Apache Druid console"

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        path = (urlparse(ctx.target.url).path or "").lower()
        if "druid" in body or path == "/druid/index.html":
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body/path marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        origin = urljoin(ctx.target.url.rstrip("/") + "/", "")
        probe_paths = [urljoin(origin, "/druid/index.html")]
        return await check_api_no_auth(
            ctx, probe_paths=probe_paths,
            success_markers=["druid", "Druid"])
