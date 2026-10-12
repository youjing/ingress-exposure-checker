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
        except Exception as e:  # noqa: BLE001
            return False, f"{type(e).__name__}: {e}"
