import pytest
from iec.models import (
    AuthStatus, Severity, STATUS_SEVERITY,
    Target, ScanResult, FingerprintResult, AuthCheckResult,
)

class TestAuthStatus:
    def test_exposed_no_auth_is_critical(self):
        assert STATUS_SEVERITY[AuthStatus.EXPOSED_NO_AUTH] == Severity.CRITICAL
    def test_exposed_default_creds_is_high(self):
        assert STATUS_SEVERITY[AuthStatus.EXPOSED_DEFAULT_CREDS] == Severity.HIGH
    def test_protected_is_ok(self):
        assert STATUS_SEVERITY[AuthStatus.PROTECTED] == Severity.OK
    def test_basic_auth_protected_is_ok(self):
        assert STATUS_SEVERITY[AuthStatus.BASIC_AUTH_PROTECTED] == Severity.OK
    def test_unknown_is_info(self):
        assert STATUS_SEVERITY[AuthStatus.UNKNOWN] == Severity.INFO
    def test_inconclusive_is_info(self):
        assert STATUS_SEVERITY[AuthStatus.INCONCLUSIVE] == Severity.INFO
    def test_all_statuses_mapped(self):
        for status in AuthStatus:
            assert status in STATUS_SEVERITY, f"{status} missing severity mapping"

class TestTarget:
    def test_target_creation(self):
        t = Target(url="http://example.com", name="test")
        assert t.url == "http://example.com" and t.name == "test"
    def test_target_default_name(self):
        t = Target(url="http://example.com")
        assert t.name == ""

class TestScanResult:
    def test_result_derives_severity_from_status(self):
        r = ScanResult(target=Target(url="http://x"), auth_status=AuthStatus.EXPOSED_NO_AUTH)
        assert r.severity == Severity.CRITICAL
    def test_result_default_severity_info(self):
        r = ScanResult(target=Target(url="http://x"))
        assert r.severity == Severity.INFO

class TestFingerprintResult:
    def test_fingerprint_result_fields(self):
        f = FingerprintResult(middleware="grafana", confidence="high", evidence=["body match"])
        assert f.middleware == "grafana" and f.version is None

class TestAuthCheckResult:
    def test_auth_check_result_fields(self):
        a = AuthCheckResult(status=AuthStatus.PROTECTED, evidence=["default creds rejected"])
        assert a.status == AuthStatus.PROTECTED
