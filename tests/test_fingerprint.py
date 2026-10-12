import pytest
from iec.fingerprint import fingerprint, HIGH, LOW
from iec.probe import ProbeContext
from iec.models import Target, FingerprintResult


class FakeCtx(ProbeContext):
    def __init__(self, body="", headers=None, favicon=None):
        super().__init__(target=Target(url="http://x"))
        self.home_body = body
        self.home_headers = headers or {}
        self.favicon_hash = favicon


@pytest.mark.asyncio
async def test_no_match_returns_none():
    from iec.plugins.base import PLUGINS
    snapshot = list(PLUGINS)
    PLUGINS.clear()
    try:
        ctx = FakeCtx(body="nothing useful")
        assert await fingerprint(ctx) is None
    finally:
        PLUGINS[:] = snapshot


@pytest.mark.asyncio
async def test_high_confidence_on_two_signals():
    from iec.plugins.base import PLUGINS, MiddlewarePlugin
    from iec.models import FingerprintResult, AuthCheckResult, AuthStatus

    class TwoSignal(MiddlewarePlugin):
        name = "twosignal"
        async def fingerprint(self, ctx):
            hits = 0
            if "grafana" in ctx.home_body:
                hits += 1
            if ctx.home_headers.get("x-some-header") == "grafana":
                hits += 1
            if hits >= 2:
                return FingerprintResult(middleware="twosignal", confidence=HIGH, evidence=["body+hdr"])
            return None
        async def check_auth(self, ctx):
            return AuthCheckResult(status=AuthStatus.UNKNOWN, evidence=[])

    snapshot = list(PLUGINS)
    PLUGINS.append(TwoSignal())
    try:
        ctx = FakeCtx(body="welcome to grafana", headers={"x-some-header": "grafana"})
        r = await fingerprint(ctx)
        assert r is not None and r.confidence == HIGH
    finally:
        PLUGINS[:] = snapshot


@pytest.mark.asyncio
async def test_low_confidence_reports_unknown():
    from iec.plugins.base import PLUGINS, MiddlewarePlugin
    from iec.models import FingerprintResult, AuthCheckResult, AuthStatus

    class OneWeak(MiddlewarePlugin):
        name = "oneweak"
        async def fingerprint(self, ctx):
            if "grafana" in ctx.home_body:
                return FingerprintResult(middleware="oneweak", confidence=LOW, evidence=["body"])
            return None
        async def check_auth(self, ctx):
            return AuthCheckResult(status=AuthStatus.UNKNOWN, evidence=[])

    snapshot = list(PLUGINS)
    PLUGINS.clear()
    PLUGINS.append(OneWeak())
    try:
        ctx = FakeCtx(body="mentioning grafana once")
        r = await fingerprint(ctx)
        assert r is not None and r.middleware == "oneweak" and r.confidence == LOW
    finally:
        PLUGINS[:] = snapshot
