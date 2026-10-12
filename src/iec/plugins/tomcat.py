from __future__ import annotations

from urllib.parse import urljoin

from iec.credcheck import check_basic_auth
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class TomcatPlugin(MiddlewarePlugin):
    name = "tomcat"
    description = "Apache Tomcat manager"
    default_creds = [("tomcat", "tomcat"), ("admin", "admin"),
                     ("manager", "manager")]

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if "apache tomcat" in body:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        origin = urljoin(ctx.target.url.rstrip("/") + "/", "")
        probe_path = urljoin(origin, "/manager/html")
        return await check_basic_auth(ctx, probe_path=probe_path,
                                      creds=self.default_creds)
