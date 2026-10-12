from __future__ import annotations

from iec.credcheck import check_api_no_auth
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class LogstashPlugin(MiddlewarePlugin):
    name = "logstash"
    service_type = "api"
    description = "Logstash monitoring API"

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if "logstash" in body:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        return await check_api_no_auth(
            ctx, probe_paths=["/_node/stats"],
            success_markers=["process", "events"])
