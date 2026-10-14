from __future__ import annotations

from urllib.parse import urlparse

from iec.models import FingerprintResult
from iec.plugins import PLUGINS
from iec.probe import ProbeContext

HIGH = "high"
LOW = "low"
URL_HINT = "url_hint"

# URL 路径关键词 → 中间件名。当 HTTP 指纹无法识别时,
# 从 URL 推断中间件类型并继续尝试检测(置信度: url_hint)。
URL_KEYWORDS: dict[str, str] = {
    "kibana": "kibana",
    "grafana": "grafana",
    "nacos": "nacos",
    "elasticsearch": "elasticsearch",
    "prometheus": "prometheus",
    "alertmanager": "alertmanager",
    "logstash": "logstash",
    "jenkins": "jenkins",
    "harbor": "harbor",
    "nexus": "nexus",
    "minio": "minio",
    "phpmyadmin": "phpmyadmin",
    "tomcat": "tomcat",
    "druid": "druid",
    "artifactory": "jfrog",
    "jfrog": "jfrog",
    "mongo-express": "mongo_express",
    "mongoexpress": "mongo_express",
    "phpinfo": "phpinfo",
    "rabbitmq": "rabbitmq",
    "chirpstack": "chirpstack",
    "swagger": "swagger",
    "api-docs": "swagger",
    "openapi": "swagger",
    "actuator": "actuator",
}


def url_hint_fingerprint(ctx: ProbeContext) -> FingerprintResult | None:
    """Fallback: infer middleware from URL host/path keywords when HTTP fingerprint fails."""
    try:
        parsed = urlparse(ctx.target.url)
        url_text = (parsed.netloc + parsed.path).lower()
    except Exception:
        return None
    for keyword, middleware in URL_KEYWORDS.items():
        if keyword in url_text:
            # 只要有对应插件已注册才返回
            if any(p.name == middleware for p in PLUGINS):
                return FingerprintResult(
                    middleware=middleware,
                    confidence=URL_HINT,
                    evidence=[f"URL contains '{keyword}' (HTTP fingerprint inconclusive)"],
                )
    return None


async def fingerprint(ctx: ProbeContext) -> FingerprintResult | None:
    """Run all plugins, return the best match; fall back to URL keywords."""
    best: FingerprintResult | None = None
    for plugin in PLUGINS:
        try:
            result = await plugin.fingerprint(ctx)
        except Exception:
            continue
        if result is None:
            continue
        if result.confidence == HIGH:
            return result
        if best is None:
            best = result
    if best is not None:
        return best
    return url_hint_fingerprint(ctx)
