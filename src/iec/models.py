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
class TestDetail:
    """单次测试的结构化详情(用于详细报告)。"""
    name: str                # 测试项名称, 如 "默认凭据测试"
    description: str         # 中文描述, 如 "使用 admin/admin 尝试登录"
    target: str = ""         # 请求的完整 URL
    credentials: str = "-"   # 使用的凭据, 如 "admin/admin"; 无则为 "-"
    request: str = ""        # 请求摘要, 如 "POST /login (form)"
    response: str = ""       # 响应摘要, 如 "HTTP 401 - Invalid username or password"
    result: str = ""         # 判定结果, 如 "登录被拒绝(存在保护)"
    vulnerable: bool = False # 是否构成漏洞


# 中文状态描述
STATUS_ZH: dict[AuthStatus, str] = {
    AuthStatus.EXPOSED_NO_AUTH: "严重：无需登录即可访问敏感接口/控制台",
    AuthStatus.EXPOSED_DEFAULT_CREDS: "高危：默认凭据可登录",
    AuthStatus.PROTECTED: "正常：已有保护，默认凭据无效",
    AuthStatus.BASIC_AUTH_PROTECTED: "正常：启用 HTTP Basic 认证",
    AuthStatus.UNKNOWN: "未知：无法识别服务或证据不足",
    AuthStatus.INCONCLUSIVE: "无法判定：测试特征不可靠",
    AuthStatus.UNREACHABLE: "不可达：目标无法连接",
    AuthStatus.ERROR: "错误：扫描过程异常",
}

SEVERITY_ZH: dict[Severity, str] = {
    Severity.CRITICAL: "严重",
    Severity.HIGH: "高危",
    Severity.INFO: "信息",
    Severity.OK: "正常",
}


@dataclass
class AuthCheckResult:
    status: AuthStatus
    evidence: list[str]
    details: list[TestDetail] = field(default_factory=list)


@dataclass
class ScanResult:
    target: Target
    middleware: str | None = None
    middleware_version: str | None = None
    auth_status: AuthStatus = AuthStatus.UNKNOWN
    evidence: list[str] = field(default_factory=list)
    details: list[TestDetail] = field(default_factory=list)
    error: str | None = None
    reachable: bool = False   # 目标是否可达(从扫描器视角即公网可达)

    @property
    def severity(self) -> Severity:
        return STATUS_SEVERITY.get(self.auth_status, Severity.INFO)

    @property
    def status_zh(self) -> str:
        return STATUS_ZH.get(self.auth_status, self.auth_status.value)

    @property
    def severity_zh(self) -> str:
        return SEVERITY_ZH.get(self.severity, self.severity.value)

    @property
    def reachable_zh(self) -> str:
        return "✅ 可达" if self.reachable else "❌ 不可达"
