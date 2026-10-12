from __future__ import annotations

from iec.models import FingerprintResult
from iec.plugins import PLUGINS
from iec.probe import ProbeContext

HIGH = "high"
LOW = "low"


async def fingerprint(ctx: ProbeContext) -> FingerprintResult | None:
    """Run all plugins, return the best match."""
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
    return best
