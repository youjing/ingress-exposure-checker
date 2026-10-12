from __future__ import annotations

from urllib.parse import urljoin

from iec.credcheck import check_basic_auth
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class MongoExpressPlugin(MiddlewarePlugin):
    name = "mongo_express"
    description = "MongoExpress MongoDB admin UI"
    default_creds = [("admin", "pass"), ("admin", "admin"), ("", "")]

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if "mongo express" in body:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        origin = urljoin(ctx.target.url.rstrip("/") + "/", "")
        probe_path = urljoin(origin, "/")
        return await check_basic_auth(ctx, probe_path=probe_path,
                                      creds=self.default_creds)
