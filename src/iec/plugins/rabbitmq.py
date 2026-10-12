from __future__ import annotations

from urllib.parse import urljoin

from iec.credcheck import check_basic_auth
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class RabbitMQPlugin(MiddlewarePlugin):
    name = "rabbitmq"
    description = "RabbitMQ Management UI"
    default_creds = [("guest", "guest")]

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if "rabbitmq management" in body or "rabbitmq" in body:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        probe_path = urljoin(ctx.target.url.rstrip("/") + "/", "api/whoami")
        return await check_basic_auth(ctx, probe_path=probe_path,
                                      creds=self.default_creds)
