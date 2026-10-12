# Ingress Exposure Checker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build CLI tool `iec` that fingerprints auth status of public Ingress endpoints from a file, detecting no-auth exposures and default-credential vulnerabilities, producing HTML/Markdown/terminal reports.

**Architecture:** Python 3.12 + httpx async fetching. Plugin-based detection engine: core framework (fingerprint engine + credential test engine) provides generic fetch/match/login flows; each middleware is a declarative plugin (fingerprint signals + detection config); adding a new middleware requires zero core changes. Data-driven, control-group anti-false-positive.

**Tech Stack:** Python 3.12, httpx, rich, jinja2, mmh3; dev: pytest, pytest-asyncio, respx.

---

## File Structure

```
ingress_exposure_checker/
├── pyproject.toml
├── README.md
├── src/iec/
│   ├── __init__.py
│   ├── cli.py              # CLI entry + authorization gate
│   ├── models.py           # data models + result types
│   ├── input.py            # TXT/CSV parsing
│   ├── http.py             # httpx async client (concurrency/limit)
│   ├── probe.py            # ProbeContext + fetch helpers
│   ├── fingerprint.py      # fingerprint engine
│   ├── credcheck.py        # credential test engine (form/basic/API)
│   ├── runner.py           # scan orchestration + result aggregation
│   ├── report/
│   │   ├── __init__.py
│   │   ├── terminal.py     # rich live output
│   │   ├── html.py         # Jinza2 self-contained HTML report
│   │   └── markdown.py     # Markdown report
│   └── plugins/
│       ├── __init__.py     # auto-registration
│       ├── base.py         # MiddlewarePlugin base + registry
│       ├── grafana.py rabbitmq.py nacos.py
│       ├── elasticsearch.py prometheus.py alertmanager.py logstash.py
│       ├── harbor.py nexus.py minio.py
│       ├── phpmyadmin.py tomcat.py mongo_express.py
│       ├── druid.py kafkaui.py phpinfo.py kibana.py jenkins.py jfrog.py
│       └── unknown.py      # generic fallback plugin
└── tests/
    ├── conftest.py
    ├── test_models.py test_input.py test_http.py test_probe.py
    ├── test_plugins_base.py test_fingerprint.py test_credcheck.py
    ├── test_plugins.py test_report.py test_cli.py test_e2e.py
```


## Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `src/iec/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Create pyproject.toml**

```toml
[project]
name = "ingress-exposure-checker"
version = "0.1.0"
description = "Scan publicly exposed Ingress endpoints for no-auth and default-credential vulnerabilities"
requires-python = ">=3.12"
dependencies = [
    "httpx>=0.27",
    "rich>=13.7",
    "jinja2>=3.1",
    "mmh3>=4.1",
]

[project.optional-dependencies]
dev = [
    "pytest>=8",
    "pytest-asyncio>=0.23",
    "respx>=0.21",
]

[project.scripts]
iec = "iec.cli:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/iec"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

- [ ] **Step 2: Create package init and test fixtures**

`src/iec/__init__.py`:
```python
__version__ = "0.1.0"
```

`tests/__init__.py`: (empty file)

`tests/conftest.py`:
```python
import pytest

@pytest.fixture
def sample_targets():
    from iec.models import Target
    return [
        Target(url="http://grafana.example.com", name="grafana-prod"),
        Target(url="http://es.example.com:9200"),
        Target(url="https://nacos.internal.example.com/nacos"),
    ]
```

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml src/iec/__init__.py tests/
git commit -m "build: project scaffolding (pyproject.toml + package structure + pytest config)"
```


## Task 2: Data Models

**Files:**
- Create: `src/iec/models.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write failing tests**

`tests/test_models.py`:
```python
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
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'iec.models'`

- [ ] **Step 3: Implement models.py**

`src/iec/models.py`:
```python
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


@dataclass
class Target:
    url: str
    name: str = ""


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
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_models.py -v`
Expected: all PASS (12 tests)

- [ ] **Step 5: Commit**

```bash
git add src/iec/models.py tests/test_models.py
git commit -m "feat(models): define AuthStatus/Severity/Target/ScanResult data models"
```


## Task 3: Input Parsing

**Files:**
- Create: `src/iec/input.py`
- Create: `tests/test_input.py`

- [ ] **Step 1: Write failing tests**

`tests/test_input.py`:
```python
import pytest
from pathlib import Path
from iec.input import parse_targets
from iec.models import Target

def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p

class TestTxtInput:
    def test_parse_one_url_per_line(self, tmp_path):
        p = _write(tmp_path, "t.txt", "http://a.com\nhttp://b.com\n")
        targets = parse_targets(p)
        assert len(targets) == 2 and targets[0].url == "http://a.com" and targets[1].url == "http://b.com"
    def test_strips_blank_lines_and_whitespace(self, tmp_path):
        p = _write(tmp_path, "t.txt", "\n  http://a.com  \n\n")
        targets = parse_targets(p)
        assert len(targets) == 1 and targets[0].url == "http://a.com"
    def test_deduplicates(self, tmp_path):
        p = _write(tmp_path, "t.txt", "http://a.com\nhttp://a.com\n")
        assert len(parse_targets(p)) == 1
    def test_rejects_non_http_scheme(self, tmp_path):
        p = _write(tmp_path, "t.txt", "ftp://a.com\n")
        with pytest.raises(ValueError, match="http/https"):
            parse_targets(p)

class TestCsvInput:
    def test_csv_with_url_column(self, tmp_path):
        p = _write(tmp_path, "t.csv", "name,url\nfoo,http://a.com\nbar,http://b.com\n")
        ts = parse_targets(p)
        assert ts[0] == Target(url="http://a.com", name="foo") and ts[1].url == "http://b.com"
    def test_csv_url_only(self, tmp_path):
        p = _write(tmp_path, "t.csv", "url\nhttp://a.com\n")
        assert parse_targets(p)[0] == Target(url="http://a.com")

class TestSchemeNormalization:
    def test_adds_http_scheme_when_missing(self, tmp_path):
        p = _write(tmp_path, "t.txt", "example.com\n")
        assert parse_targets(p)[0].url == "http://example.com"
    def test_preserves_https(self, tmp_path):
        p = _write(tmp_path, "t.txt", "https://secure.com\n")
        assert parse_targets(p)[0].url == "https://secure.com"
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_input.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement input.py**

`src/iec/input.py`:
```python
from __future__ import annotations
import csv
from pathlib import Path
from urllib.parse import urlparse
from .models import Target


def _normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty URL")
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"only http/https scheme supported, got: {parsed.scheme} ({raw})")
    return raw


def parse_targets(path) -> list[Target]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"input file not found: {path}")
    return _parse_csv(path) if path.suffix.lower() == ".csv" else _parse_txt(path)


def _parse_txt(path: Path) -> list[Target]:
    seen: set[str] = set()
    targets: list[Target] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url = _normalize_url(line)
        if url in seen:
            continue
        seen.add(url)
        targets.append(Target(url=url))
    return targets


def _parse_csv(path: Path) -> list[Target]:
    seen: set[str] = set()
    targets: list[Target] = []
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "url" not in reader.fieldnames:
            raise ValueError("CSV must have header with at least 'url' column")
        for row in reader:
            raw_url = (row.get("url") or "").strip()
            if not raw_url:
                continue
            url = _normalize_url(raw_url)
            if url in seen:
                continue
            seen.add(url)
            name = (row.get("name") or "").strip()
            targets.append(Target(url=url, name=name))
    return targets
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_input.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/iec/input.py tests/test_input.py
git commit -m "feat(input): TXT/CSV input parsing, URL normalization and dedup"
```


## Task 4: HTTP Async Client

**Files:**
- Create: `src/iec/http.py`
- Create: `tests/test_http.py`

- [ ] **Step 1: Write failing tests**

`tests/test_http.py`:
```python
import httpx
import respx
import pytest
from iec.http import HttpClient

@pytest.mark.asyncio
async def test_get_returns_response():
    async with HttpClient() as client:
        with respx.mock:
            route = respx.get("http://example.com/").mock(return_value=httpx.Response(200, text="ok"))
            resp = await client.get("http://example.com/")
            assert resp.status_code == 200 and route.called

@pytest.mark.asyncio
async def test_post_sends_json():
    async with HttpClient() as client:
        with respx.mock:
            route = respx.post("http://example.com/login").mock(return_value=httpx.Response(200, json={"ok": True}))
            resp = await client.post("http://example.com/login", json={"u": "a"})
            assert resp.status_code == 200 and route.calls[0].request.content is not None

@pytest.mark.asyncio
async def test_timeout_marks_error():
    async with HttpClient(timeout=0.001) as client:
        with respx.mock:
            respx.get("http://slow.com/").mock(side_effect=httpx.TimeoutException("slow"))
            ok, err = await client.safe_get("http://slow.com/")
            assert ok is False and ("TimeoutException" in err or "timeout" in err.lower())

@pytest.mark.asyncio
async def test_concurrency_semaphore_value():
    async with HttpClient(concurrency=2) as client:
        assert client._sem._value == 2
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_http.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement http.py**

`src/iec/http.py`:
```python
from __future__ import annotations
import asyncio
import httpx

USER_AGENT = "ingress-exposure-checker/0.1 (internal audit)"


class HttpClient:
    def __init__(self, concurrency: int = 20, per_host: int = 2,
                 timeout: float = 10.0, verify_tls: bool = True):
        self.concurrency = concurrency
        self.per_host = per_host
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._client: httpx.AsyncClient | None = None
        self._sem = asyncio.Semaphore(concurrency)
        self._host_sems: dict[str, asyncio.Semaphore] = {}

    async def __aenter__(self) -> "HttpClient":
        self._client = httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls,
                                         follow_redirects=True, headers={"User-Agent": USER_AGENT})
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _host_sem(self, host: str) -> asyncio.Semaphore:
        if host not in self._host_sems:
            self._host_sems[host] = asyncio.Semaphore(self.per_host)
        return self._host_sems[host]

    async def get(self, url: str, **kwargs) -> httpx.Response:
        host = httpx.URL(url).host
        async with self._sem, self._host_sem(host):
            assert self._client
            return await self._client.get(url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        host = httpx.URL(url).host
        async with self._sem, self._host_sem(host):
            assert self._client
            return await self._client.post(url, **kwargs)

    async def safe_get(self, url: str) -> tuple[bool, str]:
        try:
            await self.get(url)
            return True, ""
        except httpx.TimeoutException as e:
            return False, f"TimeoutException: {e}"
        except httpx.HTTPError as e:
            return False, f"{type(e).__name__}: {e}"
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_http.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/iec/http.py tests/test_http.py
git commit -m "feat(http): httpx async client with concurrency/rate-limit/timeout"
```


## Task 5: ProbeContext and Fetch Helpers

**Files:**
- Create: `src/iec/probe.py`
- Create: `tests/test_probe.py`

- [ ] **Step 1: Write failing tests**

`tests/test_probe.py`:
```python
import httpx
import respx
import pytest
from iec.http import HttpClient
from iec.models import Target
from iec.probe import ProbeContext, build_context

@pytest.mark.asyncio
async def test_build_context_fetches_home_and_favicon():
    target = Target(url="http://example.com")
    with respx.mock:
        respx.get("http://example.com/").mock(return_value=httpx.Response(200, text="<html>hi</html>"))
        respx.get("http://example.com/favicon.ico").mock(return_value=httpx.Response(200, content=b"x"))
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            assert ctx.home_body == "<html>hi</html>" and ctx.favicon_hash is not None

@pytest.mark.asyncio
async def test_build_context_handles_favicon_failure():
    target = Target(url="http://example.com")
    with respx.mock:
        respx.get("http://example.com/").mock(return_value=httpx.Response(200, text="ok"))
        respx.get("http://example.com/favicon.ico").mock(return_value=httpx.Response(404))
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            assert ctx.home_body == "ok" and ctx.favicon_hash is None

@pytest.mark.asyncio
async def test_context_fetch_path():
    target = Target(url="http://example.com")
    with respx.mock:
        respx.get("http://example.com/").mock(return_value=httpx.Response(200, text="home"))
        respx.get("http://example.com/api/health").mock(
            return_value=httpx.Response(200, text='{"status":"ok"}', headers={"Content-Type": "application/json"}))
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            status, body, headers = await ctx.fetch_path("/api/health")
            assert status == 200 and '{"status":"ok"}' in body and headers.get("content-type") == "application/json"
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_probe.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement probe.py**

`src/iec/probe.py`:
```python
from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urljoin
import httpx
import mmh3
from .http import HttpClient
from .models import Target


@dataclass
class ProbeContext:
    target: Target
    client: HttpClient
    home_body: str = ""
    home_headers: dict[str, str] = field(default_factory=dict)
    favicon_hash: int | None = None

    async def fetch_path(self, path: str) -> tuple[int, str, dict[str, str]]:
        url = urljoin(self.target.url.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = await self.client.get(url)
            return resp.status_code, resp.text, dict(resp.headers)
        except httpx.HTTPError as e:
            return 0, "", {"_error": f"{type(e).__name__}: {e}"}


async def _fetch_favicon_hash(client: HttpClient, base_url: str) -> int | None:
    url = urljoin(base_url.rstrip("/") + "/", "favicon.ico")
    try:
        resp = await client.get(url)
        if resp.status_code == 200 and resp.content:
            return mmh3.hash(resp.content)
    except httpx.HTTPError:
        pass
    return None


async def build_context(client: HttpClient, target: Target) -> ProbeContext:
    ctx = ProbeContext(target=target, client=client)
    try:
        resp = await client.get(target.url)
        ctx.home_body = resp.text
        ctx.home_headers = {k.lower(): v for k, v in resp.headers.items()}
    except httpx.HTTPError as e:
        ctx.home_headers = {"_error": f"{type(e).__name__}: {e}"}
    ctx.favicon_hash = await _fetch_favicon_hash(client, target.url)
    return ctx
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_probe.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/iec/probe.py tests/test_probe.py
git commit -m "feat(probe): ProbeContext to fetch homepage/favicon/arbitrary paths"
```

## Task 6: Plugin Base and Registry

**Files:**
- Create: `src/iec/plugins/__init__.py`
- Create: `src/iec/plugins/base.py`
- Create: `tests/test_plugins_base.py`

- [ ] **Step 1: Write failing tests**

`tests/test_plugins_base.py`:
```python
import pytest
from iec.plugins.base import MiddlewarePlugin, PLUGINS, register, get_plugin

def test_register_and_get_plugin():
    snapshot = list(PLUGINS)
    try:
        @register
        class FakePlugin(MiddlewarePlugin):
            name = "fake_test_plugin"
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
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_plugins_base.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement plugin base**

`src/iec/plugins/__init__.py`:
```python
from .base import MiddlewarePlugin, register, PLUGINS, get_plugin  # noqa: F401
```

`src/iec/plugins/base.py`:
```python
from __future__ import annotations
from abc import ABC, abstractmethod
from iec.models import FingerprintResult, AuthCheckResult
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
    service_type: str = "web_ui"          # "web_ui" | "api"
    description: str = ""
    default_creds: list[tuple[str, str]] = []   # known default credentials

    @abstractmethod
    async def fingerprint(self, ctx: ProbeContext) -> FingerprintResult | None:
        """Return fingerprint match or None if this plugin does not match."""
        ...

    @abstractmethod
    async def check_auth(self, ctx: ProbeContext) -> AuthCheckResult:
        """Run auth/no-auth/default-credential detection."""
        ...
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_plugins_base.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/iec/plugins/__init__.py src/iec/plugins/base.py tests/test_plugins_base.py
git commit -m "feat(plugins): MiddlewarePlugin base class + register/get_plugin registry"
```

## Task 7: Fingerprint Engine

**Files:**
- Create: `src/iec/fingerprint.py`
- Create: `tests/test_fingerprint.py`

- [ ] **Step 1: Write failing tests**

`tests/test_fingerprint.py`:
```python
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

def test_no_match_returns_none():
    # Temporarily clear plugins
    from iec.plugins.base import PLUGINS
    snapshot = list(PLUGINS)
    PLUGINS.clear()
    try:
        ctx = FakeCtx(body="nothing useful")
        assert fingerprint(ctx) is None
    finally:
        PLUGINS[:] = snapshot

def test_high_confidence_on_two_signals():
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
        r = fingerprint(ctx)
        assert r is not None and r.confidence == HIGH
    finally:
        PLUGINS[:] = snapshot

def test_low_confidence_reports_unknown():
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
    PLUGINS.append(OneWeak())
    try:
        ctx = FakeCtx(body="mentioning grafana once")
        r = fingerprint(ctx)
        assert r is not None and r.middleware == "oneweak" and r.confidence == LOW
    finally:
        PLUGINS[:] = snapshot
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_fingerprint.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement fingerprint.py**

`src/iec/fingerprint.py`:
```python
from __future__ import annotations
from iec.models import FingerprintResult
from iec.probe import ProbeContext
from iec.plugins.base import PLUGINS

HIGH = "high"
LOW = "low"


def fingerprint(ctx: ProbeContext) -> FingerprintResult | None:
    """Run all plugins, return the best match."""
    best: FingerprintResult | None = None
    for plugin in PLUGINS:
        try:
            result = plugin.fingerprint(ctx)
        except Exception:
            continue
        if result is None:
            continue
        if result.confidence == HIGH:
            return result
        if best is None:
            best = result
    return best
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_fingerprint.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/iec/fingerprint.py tests/test_fingerprint.py
git commit -m "feat(fingerprint): engine runs plugins, returns best HIGH/LOW match"
```

## Task 8: Credential Check Engine

**Files:**
- Create: `src/iec/credcheck.py`
- Create: `tests/test_credcheck.py`

- [ ] **Step 1: Write failing tests**

`tests/test_credcheck.py`:
```python
import httpx
import respx
import pytest
from iec.credcheck import check_default_creds, check_basic_auth, check_api_no_auth
from iec.http import HttpClient
from iec.probe import ProbeContext, build_context
from iec.models import Target, AuthStatus

@pytest.mark.asyncio
async def test_check_default_creds_success():
    target = Target(url="http://nacos.example.com/nacos/")
    with respx.mock:
        # control group: wrong creds -> 200 with login page (failure marker)
        respx.post("http://nacos.example.com/nacos/v1/auth/login").mock(
            side_effect=[
                httpx.Response(200, text="login invalid"),   # control (wrong)
                httpx.Response(200, text="accessToken: abc"),  # default creds success
            ]
        )
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            result = await check_default_creds(
                ctx, login_path="/nacos/v1/auth/login",
                user_field="username", password_field="password",
                creds=[("nacos", "nacos")],
                success_markers=["accessToken"],
                failure_markers=["login invalid", "invalid"],
            )
            assert result.status == AuthStatus.EXPOSED_DEFAULT_CREDS

@pytest.mark.asyncio
async def test_check_default_creds_protected():
    target = Target(url="http://grafana.example.com/login")
    with respx.mock:
        respx.post("http://grafana.example.com/login").mock(
            side_effect=[
                httpx.Response(200, text="invalid user"),          # control
                httpx.Response(200, text="invalid user"),           # default also fails
            ]
        )
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            result = await check_default_creds(
                ctx, login_path="/login",
                user_field="user", password_field="password",
                creds=[("admin", "admin")],
                success_markers=["redirect to /"],
                failure_markers=["invalid"],
            )
            assert result.status == AuthStatus.PROTECTED

@pytest.mark.asyncio
async def test_check_default_creds_inconclusive():
    target = Target(url="http://x.example.com/login")
    with respx.mock:
        # control group returns 200 with body that does NOT match failure marker
        respx.post("http://x.example.com/login").mock(
            return_value=httpx.Response(200, text="unexpected response")
        )
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            result = await check_default_creds(
                ctx, login_path="/login",
                user_field="user", password_field="password",
                creds=[("admin", "admin")],
                success_markers=["ok"],
                failure_markers=["invalid"],
            )
            assert result.status == AuthStatus.INCONCLUSIVE

@pytest.mark.asyncio
async def test_check_basic_auth_success():
    target = Target(url="http://rabbitmq.example.com/api/whoami")
    with respx.mock:
        route = respx.get("http://rabbitmq.example.com/api/whoami").mock(
            side_effect=[
                httpx.Response(401, headers={"WWW-Authenticate": "Basic"}),
                httpx.Response(200, json={"name": "guest", "tags": ["administrator"]}),
            ]
        )
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            result = await check_basic_auth(
                ctx, probe_path="/api/whoami", creds=[("guest", "guest")]
            )
            assert result.status == AuthStatus.EXPOSED_DEFAULT_CREDS
            assert route.call_count == 2

@pytest.mark.asyncio
async def test_check_api_no_auth_exposed():
    target = Target(url="http://es.example.com:9200")
    with respx.mock:
        respx.get("http://es.example.com:9200/_cluster/health").mock(
            return_value=httpx.Response(200, json={"cluster_name": "test", "status": "green"})
        )
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            result = await check_api_no_auth(
                ctx, probe_paths=["/_cluster/health", "/_cat/indices"],
                success_markers=["cluster_name"],
            )
            assert result.status == AuthStatus.EXPOSED_NO_AUTH

@pytest.mark.asyncio
async def test_check_api_no_auth_protected():
    target = Target(url="http://prom.example.com")
    with respx.mock:
        respx.get("http://prom.example.com/api/v1/status/buildinfo").mock(
            return_value=httpx.Response(401, text="unauthorized")
        )
        async with HttpClient() as client:
            ctx = await build_context(client, target)
            result = await check_api_no_auth(
                ctx, probe_paths=["/api/v1/status/buildinfo"],
                success_markers=["buildinfo"],
            )
            assert result.status == AuthStatus.PROTECTED
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_credcheck.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement credcheck.py**

`src/iec/credcheck.py`:
```python
from __future__ import annotations
import httpx
from iec.models import AuthStatus, AuthCheckResult
from iec.probe import ProbeContext


def _any_marker(text: str, markers: list[str]) -> bool:
    text_lower = text.lower()
    return any(m.lower() in text_lower for m in markers)


async def check_default_creds(
    ctx: ProbeContext,
    *,
    login_path: str,
    user_field: str,
    password_field: str,
    creds: list[tuple[str, str]],
    success_markers: list[str],
    failure_markers: list[str],
) -> AuthCheckResult:
    """Form-login default-credential check with control group."""
    # 1) control group: verify failure marker is reliable
    wrong_user, wrong_pass = "__invalid_user__", "__invalid_pass__"
    try:
        ctrl = await ctx.client.post(login_path, data={user_field: wrong_user, password_field: wrong_pass})
        ctrl_failed = _any_marker(ctrl.text, failure_markers) or ctrl.status_code in (401, 403)
    except httpx.HTTPError:
        return AuthCheckResult(status=AuthStatus.INCONCLUSIVE, evidence=["control request failed"])

    if not ctrl_failed:
        return AuthCheckResult(status=AuthStatus.INCONCLUSIVE,
                               evidence=["control group did not exhibit expected failure marker"])

    # 2) try default creds, stop at first success
    for user, passwd in creds:
        try:
            resp = await ctx.client.post(login_path, data={user_field: user, password_field: passwd})
        except httpx.HTTPError:
            continue
        if _any_marker(resp.text, success_markers) and resp.status_code in (200, 302):
            return AuthCheckResult(status=AuthStatus.EXPOSED_DEFAULT_CREDS,
                                   evidence=[f"default creds worked: {user}"])

    return AuthCheckResult(status=AuthStatus.PROTECTED, evidence=["default creds all failed"])


async def check_basic_auth(
    ctx: ProbeContext,
    *,
    probe_path: str,
    creds: list[tuple[str, str]],
) -> AuthCheckResult:
    """HTTP Basic Auth default-credential check."""
    for user, passwd in creds:
        try:
            resp = await ctx.client.get(probe_path, auth=(user, passwd))
        except httpx.HTTPError:
            continue
        if resp.status_code == 200:
            return AuthCheckResult(status=AuthStatus.EXPOSED_DEFAULT_CREDS,
                                   evidence=[f"basic auth worked: {user}"])
    return AuthCheckResult(status=AuthStatus.PROTECTED, evidence=["basic auth creds all failed"])


async def check_api_no_auth(
    ctx: ProbeContext,
    *,
    probe_paths: list[str],
    success_markers: list[str],
) -> AuthCheckResult:
    """Probe API endpoints without credentials; if they return sensitive data, it is exposed."""
    for path in probe_paths:
        try:
            status, body, _ = await ctx.fetch_path(path)
        except Exception:
            continue
        if status == 200 and _any_marker(body, success_markers):
            return AuthCheckResult(status=AuthStatus.EXPOSED_NO_AUTH,
                                   evidence=[f"unauthenticated access to {path}"])
        if status in (401, 403):
            return AuthCheckResult(status=AuthStatus.PROTECTED,
                                   evidence=[f"{path} requires auth (status {status})"])
    return AuthCheckResult(status=AuthStatus.UNKNOWN, evidence=["no probe path responded definitively"])
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_credcheck.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/iec/credcheck.py tests/test_credcheck.py
git commit -m "feat(credcheck): form-login, basic-auth, API no-auth checks with control group"
```

## Task 9: Middleware Plugins (Part 1 — Grafana, RabbitMQ, Nacos, Elasticsearch)

**Files:**
- Create: `src/iec/plugins/grafana.py`
- Create: `src/iec/plugins/rabbitmq.py`
- Create: `src/iec/plugins/nacos.py`
- Create: `src/iec/plugins/elasticsearch.py`
- Create: `tests/test_plugins.py`

- [ ] **Step 1: Write failing tests**

`tests/test_plugins.py`:
```python
import pytest
from iec.plugins.grafana import GrafanaPlugin
from iec.plugins.rabbitmq import RabbitMQPlugin
from iec.plugins.nacos import NacosPlugin
from iec.plugins.elasticsearch import ElasticsearchPlugin
from iec.probe import ProbeContext
from iec.models import Target, AuthStatus

class C(ProbeContext):
    def __init__(self, body="", headers=None, favicon=None):
        super().__init__(target=Target(url="http://x"))
        self.home_body = body
        self.home_headers = headers or {}
        self.favicon_hash = favicon

@pytest.mark.parametrize("body,expected", [
    ('<title>Grafana</title>', True),
    ('grafana-app', True),
    ('nothing', False),
])
def test_grafana_fingerprint(body, expected):
    p = GrafanaPlugin()
    ctx = C(body=body)
    r = p.fingerprint(ctx)
    assert (r is not None) == expected
    if expected:
        assert r.middleware == "grafana"

def test_rabbitmq_fingerprint():
    ctx = C(body="RabbitMQ Management")
    assert RabbitMQPlugin().fingerprint(ctx).middleware == "rabbitmq"

def test_nacos_fingerprint_headers():
    ctx = C(body="", headers={"content-type": "application/json"}, favicon=None)
    # nacos often identified by /nacos path API
    r = NacosPlugin().fingerprint(C(body="/nacos/v1/"))
    assert r is not None and r.middleware == "nacos"

def test_elasticsearch_fingerprint():
    ctx = C(body='{"cluster_name":"test","tagline":"You Know, for Search"}')
    r = ElasticsearchPlugin().fingerprint(ctx)
    assert r is not None and r.middleware == "elasticsearch"
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_plugins.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement plugins**

`src/iec/plugins/grafana.py`:
```python
from __future__ import annotations
from urllib.parse import urljoin
from iec.plugins.base import MiddlewarePlugin, register
from iec.models import FingerprintResult, AuthCheckResult, AuthStatus
from iec.probe import ProbeContext


@register
class GrafanaPlugin(MiddlewarePlugin):
    name = "grafana"
    description = "Grafana dashboard"
    default_creds = [("admin", "admin")]

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        markers = ("grafana", 'id="grafana"', "grafana-app")
        hits = sum(1 for m in markers if m in body)
        if hits >= 2 or "<title>grafana</title>" in body:
            return FingerprintResult(middleware=self.name, confidence="high", evidence=["body markers"])
        if hits == 1:
            return FingerprintResult(middleware=self.name, confidence="low", evidence=["weak body marker"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        from iec.credcheck import check_default_creds
        login_path = urljoin(ctx.target.url.rstrip("/") + "/", "login")
        return await check_default_creds(
            ctx, login_path=login_path,
            user_field="user", password_field="password",
            creds=self.default_creds,
            success_markers=["redirect to /", '"loggedIn":true', "grafana-user"],
            failure_markers=["invalid username", "invalid password", "does not exist", "invalid"],
        )
```

`src/iec/plugins/rabbitmq.py`:
```python
from __future__ import annotations
import httpx
from urllib.parse import urljoin
from iec.plugins.base import MiddlewarePlugin, register
from iec.models import FingerprintResult, AuthCheckResult, AuthStatus
from iec.probe import ProbeContext


@register
class RabbitMQPlugin(MiddlewarePlugin):
    name = "rabbitmq"
    description = "RabbitMQ Management UI"
    default_creds = [("guest", "guest")]

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if "rabbitmq management" in body or "rabbitmq" in body:
            return FingerprintResult(middleware=self.name, confidence="high", evidence=["body"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        from iec.credcheck import check_basic_auth
        probe_path = urljoin(ctx.target.url.rstrip("/") + "/", "api/whoami")
        return await check_basic_auth(ctx, probe_path=probe_path, creds=self.default_creds)
```

`src/iec/plugins/nacos.py`:
```python
from __future__ import annotations
import httpx
from urllib.parse import urljoin
from iec.plugins.base import MiddlewarePlugin, register
from iec.models import FingerprintResult, AuthCheckResult, AuthStatus
from iec.probe import ProbeContext


@register
class NacosPlugin(MiddlewarePlugin):
    name = "nacos"
    description = "Nacos config/registration console"
    default_creds = [("nacos", "nacos")]

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        markers = ("/nacos/", "nacos", "nacos console")
        hits = sum(1 for m in markers if m in body)
        if hits >= 2 or "/nacos/" in body:
            return FingerprintResult(middleware=self.name, confidence="high" if hits >= 2 else "low",
                                     evidence=["path/body markers"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        # Nacos without auth: API returns data directly
        from iec.credcheck import check_api_no_auth
        api_path = urljoin(ctx.target.url.rstrip("/") + "/", "nacos/v1/auth/users?pageNo=1&pageSize=1")
        no_auth = await check_api_no_auth(ctx, probe_paths=[api_path], success_markers=["totalCount", "pageItems"])
        if no_auth.status == AuthStatus.EXPOSED_NO_AUTH:
            return no_auth
        # otherwise try default creds on login
        from iec.credcheck import check_default_creds
        login_path = urljoin(ctx.target.url.rstrip("/") + "/", "nacos/v1/auth/login")
        return await check_default_creds(
            ctx, login_path=login_path,
            user_field="username", password_field="password",
            creds=self.default_creds,
            success_markers=["accessToken", "nacos"],
            failure_markers=["invalid", "error", "user not found"],
        )
```

`src/iec/plugins/elasticsearch.py`:
```python
from __future__ import annotations
from iec.plugins.base import MiddlewarePlugin, register
from iec.models import FingerprintResult, AuthCheckResult, AuthStatus
from iec.probe import ProbeContext


@register
class ElasticsearchPlugin(MiddlewarePlugin):
    name = "elasticsearch"
    service_type = "api"
    description = "Elasticsearch HTTP API"

    async def fingerprint(self, ctx: ProbeContext):
        body = ctx.home_body.lower()
        if '"cluster_name"' in body and '"tagline"' in body and "you know, for search" in body:
            return FingerprintResult(middleware=self.name, confidence="high", evidence=["root JSON"])
        return None

    async def check_auth(self, ctx: ProbeContext):
        from iec.credcheck import check_api_no_auth
        return await check_api_no_auth(ctx, probe_paths=["/_cluster/health", "/_cat/indices"],
                                       success_markers=["cluster_name", "cluster"])
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_plugins.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/iec/plugins/grafana.py src/iec/plugins/rabbitmq.py src/iec/plugins/nacos.py \
        src/iec/plugins/elasticsearch.py tests/test_plugins.py
git commit -m "feat(plugins): grafana, rabbitmq, nacos, elasticsearch plugins"
```

## Task 10: Middleware Plugins (Part 2 — Prometheus, Harbor, phpMyAdmin, Druid, Kibana, Jenkins)

**Files:**
- Create: `src/iec/plugins/prometheus.py alertmanager.py logstash.py`
- Create: `src/iec/plugins/harbor.py nexus.py minio.py`
- Create: `src/iec/plugins/phpmyadmin.py tomcat.py mongo_express.py`
- Create: `src/iec/plugins/druid.py kafkaui.py phpinfo.py kibana.py jenkins.py jfrog.py`
- Create: `src/iec/plugins/unknown.py`

Each plugin follows the same pattern (name + fingerprint + check_auth). Below are concise definitions. All use `@register`.

- [ ] **Step 1: Implement Task 10 plugins**

`src/iec/plugins/prometheus.py` — API type, probe `/api/v1/status/buildinfo` or `/-/ready`, success marker `buildinfo`. No default creds (no auth UI); reports EXPOSED_NO_AUTH if API responds unauthenticated, PROTECTED if 401/403.

`src/iec/plugins/alertmanager.py` — API type, probe `/api/v2/status`, success marker `cluster`.

`src/iec/plugins/logstash.py` — API type, probe `/_node/stats`, success marker `process`. Login path `/login` exists but no default creds → only no-auth check.

`src/iec/plugins/harbor.py` — Form login `/c/login`, user_field `principal`, password_field `password`, creds `[("admin", "Harbor12345")]`, success `redirect`, failure `invalid`.

`src/iec/plugins/nexus.py` — API login `/service/rest/v1/status` with basic auth, creds `[("admin", "admin123")]`. Fingerprint: body contains `nexus` or `Sonatype Nexus`.

`src/iec/plugins/minio.py` — API login `/minio/login` or check `/minio/health/live` + API. Fingerprint body `minio`. Creds `[("minioadmin", "minioadmin")]` via form data `accessKey`/`secretKey`.

`src/iec/plugins/phpmyadmin.py` — Form login `/index.php`, user_field `pma_username`, password_field `password`, creds `[("root", ""), ("root", "root")]`. Must first GET to extract `set_token` token, then POST with `token`. Success marker `server=`, failure `login_invalid` or `access denied`.

`src/iec/plugins/tomcat.py` — Basic auth on `/manager/html` or `/manager/status`, creds `[("tomcat", "tomcat"), ("admin", "admin"), ("manager", "manager")]`. Fingerprint body `apache tomcat`.

`src/iec/plugins/mongo_express.py` — Basic auth on `/`, creds `[("admin", "pass"), ("admin", "admin"), ("", "")]`. Fingerprint body `mongo express`.

`src/iec/plugins/druid.py` — No-auth access check `/druid/index.html` or `/druid/submitLogin`, success marker `druid`. Fingerprint path `/druid/index.html`.

`src/iec/plugins/kafkaui.py` — No-auth access check `/` or `/api/brokers`, success marker `brokers`. Fingerprint body `kafka` + `topics` or title `Kafka UI`.

`src/iec/plugins/phpinfo.py` — Fingerprint body `<title>phpinfo()</title>` or `PHP Version`. No auth check (info-only page), reports EXPOSED_NO_AUTH if reachable (it is always a finding).

`src/iec/plugins/kibana.py` — No-auth check `/api/status` (returns JSON with status) or check if login page is bypassed. Fingerprint body `kibana`. No default creds → only no-auth.

`src/iec/plugins/jenkins.py` — No-auth check: if `/manage` or `/script` reachable without login → EXPOSED_NO_AUTH; if login page `/login` → PROTECTED. Fingerprint body `jenkins`.

`src/iec/plugins/jfrog.py` — Form login `/ui/login`, user_field `user`, password_field `password`, creds `[("admin", "password")]`. Fingerprint body `jfrog` or `artifactory`.

`src/iec/plugins/unknown.py`:
```python
from iec.plugins.base import MiddlewarePlugin, register
from iec.models import FingerprintResult, AuthCheckResult, AuthStatus
from iec.probe import ProbeContext

@register
class UnknownPlugin(MiddlewarePlugin):
    name = "unknown"
    description = "Generic fallback"

    async def fingerprint(self, ctx: ProbeContext):
        return None  # unknown is the absence of a match

    async def check_auth(self, ctx: ProbeContext):
        # Generic signals only, no conclusion
        body = (ctx.home_body or "").lower()
        headers = {k.lower(): v.lower() for k, v in ctx.home_headers.items()}
        evidence = []
        if headers.get("www-authenticate", "").startswith("basic"):
            evidence.append("HTTP Basic Auth challenge present")
        if "login" in body or "sign in" in body:
            evidence.append("login page detected")
        status = AuthStatus.BASIC_AUTH_PROTECTED if evidence and "Basic Auth" in str(evidence) else AuthStatus.UNKNOWN
        return AuthCheckResult(status=status, evidence=evidence or ["no auth signal detected"])
```

- [ ] **Step 2: Commit**

```bash
git add src/iec/plugins/
git commit -m "feat(plugins): prometheus, harbor, phpmyadmin, druid, kibana, jenkins, jfrog + unknown fallback"
```

## Task 11: Runner (Scan Orchestration)

**Files:**
- Create: `src/iec/runner.py`
- Create: `tests/test_runner.py`

- [ ] **Step 1: Write failing tests**

`tests/test_runner.py`:
```python
import asyncio
import httpx
import respx
import pytest
from iec.runner import scan_target, scan_all
from iec.models import Target, AuthStatus
from iec.plugins.base import PLUGINS, MiddlewarePlugin
from iec.models import FingerprintResult, AuthCheckResult

class GrafanaPlugin(MiddlewarePlugin):
    name = "grafana"
    async def fingerprint(self, ctx):
        if "grafana" in (ctx.home_body or "").lower():
            return FingerprintResult(middleware="grafana", confidence="high", evidence=["body"])
        return None
    async def check_auth(self, ctx):
        return AuthCheckResult(status=AuthStatus.PROTECTED, evidence=["mock"])

@pytest.mark.asyncio
async def test_scan_target_matches_and_checks():
    snapshot = list(PLUGINS)
    PLUGINS.append(GrafanaPlugin())
    try:
        with respx.mock:
            respx.get("http://grafana.example.com/").mock(
                return_value=httpx.Response(200, text="<html>grafana</html>"))
            respx.get("http://grafana.example.com/favicon.ico").mock(
                return_value=httpx.Response(404))
            result = await scan_target(Target(url="http://grafana.example.com/"))
            assert result.middleware == "grafana"
            assert result.auth_status == AuthStatus.PROTECTED
    finally:
        PLUGINS[:] = snapshot

@pytest.mark.asyncio
async def test_scan_target_unreachable():
    with respx.mock:
        respx.get("http://down.example.com/").mock(side_effect=httpx.ConnectError("down"))
        respx.get("http://down.example.com/favicon.ico").mock(side_effect=httpx.ConnectError("down"))
        result = await scan_target(Target(url="http://down.example.com/"))
        assert result.auth_status in (AuthStatus.UNREACHABLE, AuthStatus.ERROR)

@pytest.mark.asyncio
async def test_scan_all_runs_multiple():
    snapshot = list(PLUGINS)
    PLUGINS.append(GrafanaPlugin())
    try:
        with respx.mock:
            respx.get("http://g1.example.com/").mock(return_value=httpx.Response(200, text="grafana"))
            respx.get("http://g1.example.com/favicon.ico").mock(return_value=httpx.Response(404))
            respx.get("http://g2.example.com/").mock(return_value=httpx.Response(200, text="grafana"))
            respx.get("http://g2.example.com/favicon.ico").mock(return_value=httpx.Response(404))
            results = await scan_all([Target(url="http://g1.example.com/"), Target(url="http://g2.example.com/")],
                                     concurrency=5, timeout=5, on_found=None)
            assert len(results) == 2
            assert all(r.middleware == "grafana" for r in results)
    finally:
        PLUGINS[:] = snapshot
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_runner.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement runner.py**

`src/iec/runner.py`:
```python
from __future__ import annotations
import asyncio
from typing import Callable
from iec.http import HttpClient
from iec.probe import build_context
from iec.fingerprint import fingerprint, LOW
from iec.plugins.base import get_plugin
from iec.models import Target, ScanResult, AuthStatus, AuthCheckResult


async def scan_target(
    target: Target,
    *,
    concurrency: int = 20,
    timeout: float = 10.0,
    verify_tls: bool = True,
    on_found: Callable[[ScanResult], None] | None = None,
) -> ScanResult:
    result = ScanResult(target=target)
    try:
        async with HttpClient(concurrency=concurrency, per_host=2, timeout=timeout, verify_tls=verify_tls) as client:
            ctx = await build_context(client, target)
            fp = fingerprint(ctx)
            if fp is None:
                result.auth_status = AuthStatus.UNKNOWN
                result.evidence.append("no fingerprint match")
            else:
                result.middleware = fp.middleware
                result.middleware_version = fp.version
                result.evidence.extend(fp.evidence)
                plugin = get_plugin(fp.middleware)
                if plugin is None:
                    result.auth_status = AuthStatus.UNKNOWN
                    result.evidence.append("fingerprint matched but no plugin loaded")
                elif fp.confidence == LOW:
                    result.auth_status = AuthStatus.UNKNOWN
                    result.evidence.append("low-confidence fingerprint; auth check skipped to avoid false positives")
                else:
                    check = await plugin.check_auth(ctx)
                    result.auth_status = check.status
                    result.evidence.extend(check.evidence)
    except Exception as e:
        result.auth_status = AuthStatus.ERROR
        result.error = f"{type(e).__name__}: {e}"
    if on_found and result.auth_status in (AuthStatus.EXPOSED_NO_AUTH, AuthStatus.EXPOSED_DEFAULT_CREDS):
        on_found(result)
    return result


async def scan_all(
    targets: list[Target],
    *,
    concurrency: int = 20,
    timeout: float = 10.0,
    verify_tls: bool = True,
    on_found: Callable[[ScanResult], None] | None = None,
) -> list[ScanResult]:
    sem = asyncio.Semaphore(concurrency)

    async def _one(t: Target) -> ScanResult:
        async with sem:
            return await scan_target(t, concurrency=concurrency, timeout=timeout,
                                     verify_tls=verify_tls, on_found=on_found)

    return await asyncio.gather(*(_one(t) for t in targets))
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_runner.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/iec/runner.py tests/test_runner.py
git commit -m "feat(runner): scan_target + scan_all orchestration with concurrency"
```
## Task 12: Reports (Terminal, HTML, Markdown)

**Files:**
- Create: `src/iec/report/__init__.py terminal.py html.py markdown.py`
- Create: `tests/test_report.py`

- [ ] **Step 1: Write failing tests**

`tests/test_report.py`:
```python
import pytest
from iec.report.terminal import render_terminal_summary
from iec.report.html import render_html
from iec.report.markdown import render_markdown
from iec.models import Target, ScanResult, AuthStatus, Severity

@pytest.fixture
def sample_results():
    return [
        ScanResult(target=Target(url="http://nacos.ex.com", name="nacos"),
                    middleware="nacos", auth_status=AuthStatus.EXPOSED_NO_AUTH,
                    evidence=["unauthenticated API access"]),
        ScanResult(target=Target(url="http://grafana.ex.com"),
                    middleware="grafana", auth_status=AuthStatus.EXPOSED_DEFAULT_CREDS,
                    evidence=["admin/admin worked"]),
        ScanResult(target=Target(url="http://safe.ex.com"),
                    middleware="jenkins", auth_status=AuthStatus.PROTECTED,
                    evidence=["login required"]),
        ScanResult(target=Target(url="http://unknown.ex.com"),
                    auth_status=AuthStatus.UNKNOWN, evidence=["no fingerprint"]),
    ]

def test_terminal_summary_contains_counts(sample_results, capsys):
    render_terminal_summary(sample_results)
    out = capsys.readouterr().out
    assert "CRITICAL" in out
    assert "HIGH" in out
    assert "nacos" in out

def test_html_report_is_self_contained(sample_results):
    html = render_html(sample_results)
    assert "<html" in html.lower()
    assert "nacos.ex.com" in html
    assert "<style" in html  # inlined CSS for self-contained file

def test_markdown_report_has_table(sample_results):
    md = render_markdown(sample_results)
    assert "# Ingress Exposure Scan Report" in md
    assert "| Endpoint |" in md
    assert "nacos.ex.com" in md
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_report.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement reports**

`src/iec/report/__init__.py`: empty file.

`src/iec/report/terminal.py`:
```python
from iec.models import ScanResult, AuthStatus, Severity

COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.OK: "green",
    Severity.INFO: "dim",
}

def render_terminal_summary(results: list[ScanResult]) -> None:
    from rich.console import Console
    from rich.table import Table
    from collections import Counter

    console = Console()
    counts = Counter(r.auth_status for r in results)
    console.print(f"
[bold]Total endpoints scanned:[/bold] {len(results)}")
    console.print(f"[bold red]  EXPOSED_NO_AUTH (CRITICAL):[/bold red] {counts.get(AuthStatus.EXPOSED_NO_AUTH, 0)}")
    console.print(f"[bold yellow]  EXPOSED_DEFAULT_CREDS (HIGH):[/bold yellow] {counts.get(AuthStatus.EXPOSED_DEFAULT_CREDS, 0)}")

    table = Table(title="Findings (sorted by severity)")
    table.add_column("Severity")
    table.add_column("Endpoint")
    table.add_column("Middleware")
    table.add_column("Status")
    table.add_column("Evidence")
    for r in sorted(results, key=lambda x: x.severity.value):
        table.add_row(
            f"[{COLORS[r.severity]}]{r.severity.value}[/{COLORS[r.severity]}]",
            r.target.url,
            r.middleware or "-",
            r.auth_status.value,
            "; ".join(r.evidence[:2]) or "-",
        )
    console.print(table)
```

`src/iec/report/html.py`:
```python
from iec.models import ScanResult
from jinja2 import Template

CSS = "body{font-family:system-ui,sans-serif;margin:24px;background:#fafafa}
h1{font-size:20px}.cards{display:flex;gap:12px;margin:16px 0}
.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:12px 16px;flex:1}
.card .n{font-size:28px;font-weight:700}.c{color:#b91c1c}.h{color:#b45309}.o{color:#15803d}
table{border-collapse:collapse;width:100%;background:#fff;border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #eee;font-size:13px}
th{background:#f3f4f6}code{background:#f3f4f6;padding:1px 4px;border-radius:3px}"

HTML_TEMPLATE = Template('''<!doctype html>
<html><head><meta charset="utf-8"><title>Ingress Exposure Report</title>
<style>' + CSS + '</style></head><body>
<h1>Ingress Exposure Scan Report</h1>
<p>{{ results | length }} endpoints scanned</p>
<div class="cards">
  <div class="card"><div class="n c">{{ counts.no_auth }}</div><div>EXPOSED_NO_AUTH (CRITICAL)</div></div>
  <div class="card"><div class="n h">{{ counts.default_creds }}</div><div>EXPOSED_DEFAULT_CREDS (HIGH)</div></div>
  <div class="card"><div class="n o">{{ counts.protected }}</div><div>Protected</div></div>
</div>
<table>
<tr><th>Severity</th><th>Endpoint</th><th>Middleware</th><th>Status</th><th>Evidence</th></tr>
{% for r in results | sort(attribute='severity.value') %}
<tr>
<td><span class="{{ r.severity.value }}">{{ r.severity.value }}</span></td>
<td><code>{{ r.target.url }}</code></td>
<td>{{ r.middleware or '-' }}</td>
<td>{{ r.auth_status.value }}</td>
<td>{{ '; '.join(r.evidence[:3]) }}</td>
</tr>
{% endfor %}
</table></body></html>''')


def render_html(results: list[ScanResult]) -> str:
    from collections import Counter
    counts = Counter(r.auth_status for r in results)
    return HTML_TEMPLATE.render(
        results=results,
        counts={
            "no_auth": counts.get("exposed_no_auth", 0),
            "default_creds": counts.get("exposed_default_creds", 0),
            "protected": counts.get("protected", 0) + counts.get("basic_auth_protected", 0),
        },
    )
```

`src/iec/report/markdown.py`:
```python
from iec.models import ScanResult

def render_markdown(results: list[ScanResult]) -> str:
    from collections import Counter
    counts = Counter(r.auth_status for r in results)
    lines = [
        "# Ingress Exposure Scan Report",
        "",
        f"**Total endpoints scanned:** {len(results)}",
        "",
        f"- **CRITICAL (EXPOSED_NO_AUTH):** {counts.get('exposed_no_auth', 0)}",
        f"- **HIGH (EXPOSED_DEFAULT_CREDS):** {counts.get('exposed_default_creds', 0)}",
        "",
        "| Severity | Endpoint | Middleware | Status | Evidence |",
        "|---|---|---|---|---|",
    ]
    for r in sorted(results, key=lambda x: x.severity.value):
        evidence = "; ".join(r.evidence[:3]).replace("|", "/") or "-"
        lines.append(f"| {r.severity.value} | `{r.target.url}` | {r.middleware or '-'} | {r.auth_status.value} | {evidence} |")
    return "
".join(lines)
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_report.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/iec/report/ tests/test_report.py
git commit -m "feat(report): terminal (rich), HTML (Jinja2 self-contained), Markdown reports"
```

## Task 13: CLI Entry Point

**Files:**
- Create: `src/iec/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests**

`tests/test_cli.py`:
```python
import pytest
from unittest.mock import patch
from iec.cli import main

def test_cli_refuses_without_authorized():
    with patch("sys.argv", ["iec", "targets.txt"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code != 0

def test_cli_help_shows_authorized_flag(capsys):
    with patch("sys.argv", ["iec", "--help"]):
        with pytest.raises(SystemExit):
            main()
    out = capsys.readouterr().out
    assert "--authorized" in out
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement cli.py**

`src/iec/cli.py`:
```python
from __future__ import annotations
import argparse
import asyncio
import sys
from pathlib import Path
from iec import __version__
from iec.input import parse_targets
from iec.runner import scan_all
from iec.report.terminal import render_terminal_summary
from iec.report.html import render_html
from iec.report.markdown import render_markdown


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iec",
        description="Scan publicly exposed Ingress endpoints for no-auth / default-credential vulnerabilities.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("input", help="Path to TXT/CSV file listing endpoint URLs")
    p.add_argument("--authorized", action="store_true", required=True,
                   help="Declare you have authorization to scan the listed targets.")
    p.add_argument("--output-html", default="report.html", help="HTML report output path")
    p.add_argument("--output-md", default="report.md", help="Markdown report output path")
    p.add_argument("--concurrency", type=int, default=20, help="Global concurrency (default 20)")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds")
    p.add_argument("--insecure-tls", action="store_true", help="Skip TLS certificate verification")
    return p


async def _run(args: argparse.Namespace) -> int:
    targets = parse_targets(Path(args.input))
    print(f"Loaded {len(targets)} targets from {args.input}")

    results: list = []

    def on_found(result) -> None:
        results.append(result)

    scanned = await scan_all(
        targets,
        concurrency=args.concurrency,
        timeout=args.timeout,
        verify_tls=not args.insecure_tls,
        on_found=on_found,
    )

    render_terminal_summary(scanned)

    Path(args.output_html).write_text(render_html(scanned), encoding="utf-8")
    Path(args.output_md).write_text(render_markdown(scanned), encoding="utf-8")
    print(f"\nHTML report: {args.output_html}")
    print(f"Markdown report: {args.output_md}")

    critical = sum(1 for r in scanned if r.auth_status.value == "exposed_no_auth")
    high = sum(1 for r in scanned if r.auth_status.value == "exposed_default_creds")
    return 2 if critical else (1 if high else 0)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    exit_code = asyncio.run(_run(args))
    sys.exit(exit_code)
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_cli.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/iec/cli.py tests/test_cli.py
git commit -m "feat(cli): iec CLI with --authorized gate, HTML/Markdown output"
```

## Task 14: End-to-End Integration Test

**Files:**
- Create: `tests/test_e2e.py`

- [ ] **Step 1: Write e2e test**

`tests/test_e2e.py`:
```python
import httpx
import respx
import pytest
from iec.cli import main
from iec.plugins.base import PLUGINS, MiddlewarePlugin
from iec.models import FingerprintResult, AuthCheckResult, AuthStatus, Target

class MockGrafana(MiddlewarePlugin):
    name = "grafana"
    async def fingerprint(self, ctx):
        if "grafana" in (ctx.home_body or "").lower():
            return FingerprintResult(middleware="grafana", confidence="high", evidence=["body"])
        return None
    async def check_auth(self, ctx):
        return AuthCheckResult(status=AuthStatus.EXPOSED_DEFAULT_CREDS, evidence=["mock default creds"])

@pytest.mark.asyncio
async def test_e2e_generates_reports(tmp_path):
    snapshot = list(PLUGINS)
    PLUGINS.append(MockGrafana())
    try:
        input_file = tmp_path / "targets.txt"
        input_file.write_text("http://grafana.ex.com/\nhttp://plain.ex.com/\n", encoding="utf-8")
        html_out = tmp_path / "out.html"
        md_out = tmp_path / "out.md"
        with respx.mock:
            respx.get("http://grafana.ex.com/").mock(return_value=httpx.Response(200, text="grafana"))
            respx.get("http://grafana.ex.com/favicon.ico").mock(return_value=httpx.Response(404))
            respx.get("http://plain.ex.com/").mock(return_value=httpx.Response(200, text="hello"))
            respx.get("http://plain.ex.com/favicon.ico").mock(return_value=httpx.Response(404))
            from unittest.mock import patch
            with patch("sys.argv", ["iec", str(input_file), "--authorized",
                                  "--output-html", str(html_out), "--output-md", str(md_out)]):
                with pytest.raises(SystemExit) as exc:
                    main()
                assert exc.value.code == 1  # HIGH present
        assert html_out.exists() and "grafana" in html_out.read_text(encoding="utf-8")
        assert md_out.exists() and "grafana" in md_out.read_text(encoding="utf-8")
    finally:
        PLUGINS[:] = snapshot
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/test_e2e.py -v`
Expected: PASS

- [ ] **Step 3: Run full suite**

Run: `pytest tests/ -v`
Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add tests/test_e2e.py
git commit -m "test(e2e): full CLI run generates HTML/Markdown reports"
```

## Task 15: README and Usage

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README.md**

```markdown
# ingress-exposure-checker (`iec`)

扫描公网暴露的 Ingress endpoint，检测无鉴权访问与默认凭据漏洞。

## 安装

```bash
pip install -e ".[dev]"
```

## 使用

准备目标文件（每行一个 URL，或 CSV 含 `url`/`name` 列）：

```
http://grafana.example.com
http://nacos.internal.example.com/nacos
```

运行：

```bash
iec targets.txt --authorized --output-html report.html --output-md report.md
```

> `--authorized` 为必填项，声明你对目标拥有测试授权。

## 报告

- 终端实时输出（rich）
- HTML 自包含单文件报告
- Markdown 报告

## 风险分级

| 状态 | 含义 | 级别 |
|---|---|---|
| EXPOSED_NO_AUTH | 控制台/敏感 API 无需登录直接可访问 | CRITICAL |
| EXPOSED_DEFAULT_CREDS | 有登录，默认凭据可登录 | HIGH |
| PROTECTED | 有登录，默认凭据失败 | OK |
| BASIC_AUTH_PROTECTED | HTTP Basic 认证挑战 | OK |
| UNKNOWN | 未知应用，仅报告观察信号 | INFO |

## 支持的中间件

Grafana, RabbitMQ Management, Nacos, Elasticsearch, Prometheus, Alertmanager,
Logstash, Harbor, Nexus, MinIO, phpMyAdmin, Tomcat Manager, Mongo Express,
Druid, Kafka UI, phpinfo, Kibana, Jenkins, JFrog Artifactory。

新增中间件：在 `src/iec/plugins/` 添加一个 `MiddlewarePlugin` 子类并用 `@register` 装饰即可。
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: README with install, usage, risk levels, supported middleware"
```
