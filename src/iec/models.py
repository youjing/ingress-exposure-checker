from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


class AuthStatus(str, Enum):
    EXPOSED_NO_AUTH = "exposed_no_auth"
    EXPOSED_DEFAULT_CREDS = "exposed_default_creds"
    PROTECTED = "protected"
    BASIC_AUTH_PROTECTED = "basic_auth_protected"
    UNKNOWN = "unknown"
    INCONCLUSIVE = "inconclusive"
    UNREACHABLE = "unreachable"
    ERROR = "error"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    INFO = "info"
    OK = "ok"


STATUS_SEVERITY: dict[AuthStatus, Severity] = {
    AuthStatus.EXPOSED_NO_AUTH: Severity.CRITICAL,
    AuthStatus.EXPOSED_DEFAULT_CREDS: Severity.HIGH,
    AuthStatus.PROTECTED: Severity.OK,
    AuthStatus.BASIC_AUTH_PROTECTED: Severity.OK,
    AuthStatus.UNKNOWN: Severity.INFO,
    AuthStatus.INCONCLUSIVE: Severity.INFO,
    AuthStatus.UNREACHABLE: Severity.INFO,
    AuthStatus.ERROR: Severity.INFO,
}

SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.INFO: 2,
    Severity.OK: 3,
}


@dataclass
class Target:
    url: str
    name: str = ""
    namespace: str = ""


@dataclass
class FingerprintResult:
    middleware: str
    confidence: str          # "high" | "low"
    evidence: list[str]
    version: str | None = None


@dataclass
class AuthCheckResult:
    status: AuthStatus
    evidence: list[str]


@dataclass
class ScanResult:
    target: Target
    middleware: str | None = None
    middleware_version: str | None = None
    auth_status: AuthStatus = AuthStatus.UNKNOWN
    evidence: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def severity(self) -> Severity:
        return STATUS_SEVERITY.get(self.auth_status, Severity.INFO)
