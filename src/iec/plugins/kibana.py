from __future__ import annotations

from iec.credcheck import check_api_no_auth
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class KibanaPlugin(MiddlewarePlugin):
    name = "kibana"
    service_type = "api"
    description = "Kibana UI / API"

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if "kibana" in body:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        return await check_api_no_auth(
            ctx, probe_paths=["/api/status"],
            success_markers=["status", "metrics"])
