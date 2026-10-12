from __future__ import annotations

from urllib.parse import urljoin

from iec.credcheck import check_api_no_auth
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class KafkaUIPlugin(MiddlewarePlugin):
    name = "kafkaui"
    description = "Kafka UI dashboard"

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        title = ""
        if "<title>" in body and "</title>" in body:
            title = body.split("<title>", 1)[1].split("</title>", 1)[0]
        has_title_ui = "kafka ui" in title
        if "kafka" in body and ("topics" in body or has_title_ui):
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body/title marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        origin = urljoin(ctx.target.url.rstrip("/") + "/", "")
        probe_paths = [urljoin(origin, "/"), urljoin(origin, "/api/brokers")]
        return await check_api_no_auth(
            ctx, probe_paths=probe_paths,
            success_markers=["brokers", "topics", "cluster"])
