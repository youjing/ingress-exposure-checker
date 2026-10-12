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
        # Real Logstash API root returns JSON mentioning logstash; a mere textual
        # mention (e.g. inside Kibana UI bundles) is not a fingerprint.
        if "logstash" in body and ("<html" not in body and "<!doctype" not in body):
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["json body marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        return await check_api_no_auth(
            ctx, probe_paths=["/_node/stats"],
            success_markers=["process", "events"])
