from __future__ import annotations

from iec.credcheck import check_api_no_auth
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class ElasticsearchPlugin(MiddlewarePlugin):
    name = "elasticsearch"
    service_type = "api"
    description = "Elasticsearch HTTP API"

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if ('"cluster_name"' in body and '"tagline"' in body
                and "you know, for search" in body):
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["root JSON"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        return await check_api_no_auth(
            ctx, probe_paths=["/_cluster/health", "/_cat/indices"],
            success_markers=["cluster_name", "cluster"])
