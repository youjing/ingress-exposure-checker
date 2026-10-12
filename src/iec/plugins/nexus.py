from __future__ import annotations

from urllib.parse import urljoin

from iec.credcheck import check_basic_auth
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


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
        origin = urljoin(ctx.target.url.rstrip("/") + "/", "")
        probe_path = urljoin(origin, "/service/rest/v1/status")
        return await check_basic_auth(ctx, probe_path=probe_path,
                                      creds=self.default_creds)
