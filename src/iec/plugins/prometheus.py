from __future__ import annotations

from iec.credcheck import check_api_no_auth
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class PrometheusPlugin(MiddlewarePlugin):
    name = "prometheus"
    service_type = "api"
    description = "Prometheus monitoring API"

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        title = ""
        if "<title>" in body and "</title>" in body:
            title = body.split("<title>", 1)[1].split("</title>", 1)[0]
        if "prometheus" in body or "prometheus" in title:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body/title marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        return await check_api_no_auth(
            ctx, probe_paths=["/api/v1/status/buildinfo", "/-/ready", "/-/healthy"],
            success_markers=["buildinfo", "prometheus"])
