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
        raise FileNotFoundError(f"输入文件不存在: {path}\n请检查路径是否正确;可用 list-ingress.sh 从集群导出目标清单")
    content = path.read_text(encoding="utf-8")
    if _is_ingress_table(content):
        return _parse_ingress_table(content)
    return _parse_csv(path) if path.suffix.lower() == ".csv" else _parse_txt(path)


def _is_ingress_table(content: str) -> bool:
    """Detect the kubectl-describe style ingress table format."""
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        upper = stripped.upper()
        return upper.startswith("NAMESPACE") and "HOSTS" in upper and "PORTS" in upper
    return False


def _clean_path(raw_path: str) -> str:
    """Clean an ingress path (may contain regex like /foo(/|$)(.*)) into a literal URL path.

    Examples:
        /nacos                -> /nacos
        /cws/app(/|$)(.*) -> /cws/app
        /grafana(/|$)(.*)     -> /grafana
        /                    -> /
        (empty)              -> /
    """
    import re

    path = raw_path.strip()
    if not path:
        return "/"
    # Strip everything from the first '(' (start of regex group) onward
    path = path.split("(", 1)[0]
    path = path.rstrip("$")
    if not path:
        return "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def _build_url(host: str, paths: str, ports: str) -> str:
    """Build URL from host/paths/ports. Use https if 443 present."""
    import re

    scheme = "https" if "443" in ports else "http"
    host = host.strip()
    path = _clean_path(paths)
    return f"{scheme}://{host}{path}"


def _parse_ingress_table(content: str) -> list[Target]:
    """Parse NAMESPACE/NAME/HOSTS/PATHS/PORTS table (e.g. kubectl get ingress -o wide)."""
    import re

    seen: set[str] = set()
    targets: list[Target] = []
    lines = content.splitlines()
    if not lines:
        return targets

    # Find header line
    header_line = None
    for line in lines:
        if line.strip().upper().startswith("NAMESPACE"):
            header_line = line
            break
    if header_line is None:
        return targets

    # Locate each column by its header keyword as a whole word (so NAME doesn't match inside NAMESPACE)
    headers = ["NAMESPACE", "NAME", "HOSTS", "PATHS", "PORTS"]
    positions: dict[str, int] = {}
    for h in headers:
        pattern = r'(?:^|(?<=\s))' + re.escape(h) + r'(?=\s|$)'
        m = re.search(pattern, header_line.upper())
        if m is None:
            return targets
        positions[h] = m.start()

    # Rows are between header and next blank line / end
    header_idx = lines.index(header_line)
    for line in lines[header_idx + 1:]:
        stripped = line.strip()
        if not stripped:
            break  # table ends at blank line

        def _col(name: str) -> str:
            start = positions[name]
            # end at next column's start or end of line
            end = len(line)
            for other_name, other_pos in positions.items():
                if other_pos > positions[name] and other_pos < end:
                    end = other_pos
            return line[start:end].strip()

        namespace = _col("NAMESPACE")
        name = _col("NAME")
        host = _col("HOSTS")
        paths = _col("PATHS")
        ports = _col("PORTS")

        if not host:
            continue
        url = _build_url(host, paths, ports)
        if url in seen:
            continue
        seen.add(url)
        targets.append(Target(url=url, name=name, namespace=namespace))
    return targets


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
