from __future__ import annotations

from urllib.parse import urljoin

from iec.credcheck import check_default_creds
from iec.models import FingerprintResult
from iec.plugins.base import MiddlewarePlugin, register
from iec.probe import ProbeContext


@register
class MinioPlugin(MiddlewarePlugin):
    name = "minio"
    description = "MinIO object storage"
    default_creds = [("minioadmin", "minioadmin")]

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if "minio" in body:
            return FingerprintResult(middleware=self.name, confidence="high",
                                     evidence=["body marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        origin = urljoin(ctx.target.url.rstrip("/") + "/", "")
        login_path = urljoin(origin, "/minio/login")
        return await check_default_creds(
            ctx, login_path=login_path,
            user_field="accessKey", password_field="secretKey",
            creds=self.default_creds,
            success_markers=["token", "sessionId"],
            failure_markers=["invalid"])
