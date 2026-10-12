import pytest
from iec.plugins.base import MiddlewarePlugin, PLUGINS, register, get_plugin


def test_register_and_get_plugin():
    snapshot = list(PLUGINS)
    try:
        @register
        class FakePlugin(MiddlewarePlugin):
            name = "fake_test_plugin"

            async def fingerprint(self, ctx):
                return None

            async def check_auth(self, ctx):
                from iec.models import AuthCheckResult, AuthStatus

                return AuthCheckResult(status=AuthStatus.UNKNOWN, evidence=[])

        assert any(p.name == "fake_test_plugin" for p in PLUGINS)
        assert get_plugin("fake_test_plugin") is not None
        assert get_plugin("nonexistent") is None
    finally:
        PLUGINS[:] = snapshot


def test_plugin_has_required_interface():
    for cls in MiddlewarePlugin.__subclasses__():
        inst = cls()
        assert callable(getattr(inst, "fingerprint", None))
        assert callable(getattr(inst, "check_auth", None))
