from __future__ import annotations

from abc import ABC, abstractmethod

from iec.models import AuthCheckResult, FingerprintResult
from iec.probe import ProbeContext

PLUGINS: list[MiddlewarePlugin] = []


def register(cls):
    """Class decorator: instantiate plugin and add to registry."""
    PLUGINS.append(cls())
    return cls


def get_plugin(name: str) -> MiddlewarePlugin | None:
    for p in PLUGINS:
        if p.name == name:
            return p
    return None


class MiddlewarePlugin(ABC):
    name: str = ""
    service_type: str = "web_ui"  # "web_ui" | "api"
    description: str = ""
    default_creds: list[tuple[str, str]] = []  # known default credentials

    @abstractmethod
    async def fingerprint(self, ctx: ProbeContext) -> FingerprintResult | None:
        """Return fingerprint match or None if this plugin does not match."""
        ...

    @abstractmethod
    async def check_auth(self, ctx: ProbeContext) -> AuthCheckResult:
        """Run auth/no-auth/default-credential detection."""
        ...
