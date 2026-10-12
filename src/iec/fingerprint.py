from __future__ import annotations

import asyncio
import inspect

from iec.models import FingerprintResult
from iec.plugins.base import PLUGINS
from iec.probe import ProbeContext

HIGH = "high"
LOW = "low"


def fingerprint(ctx: ProbeContext) -> FingerprintResult | None:
    """Run all plugins, return the best match."""
    best: FingerprintResult | None = None
    for plugin in PLUGINS:
        try:
            result = plugin.fingerprint(ctx)
            if inspect.iscoroutine(result):
                result = asyncio.run(result)
        except Exception:
            continue
        if result is None:
            continue
        if result.confidence == HIGH:
            return result
        if best is None:
            best = result
    return best
