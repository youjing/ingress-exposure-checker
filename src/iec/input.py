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
