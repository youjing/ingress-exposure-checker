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
