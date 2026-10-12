from iec.models import ScanResult, AuthStatus, SEVERITY_RANK
from jinja2 import Template

CSS = (
    "body{font-family:system-ui,sans-serif;margin:24px;background:"
    "#fafafa"
    "}\n"
    "h1{font-size:20px}.cards{display:flex;gap:12px;margin:16px 0}\n"
    ".card{background:"
    "#fff"
    ";border:1px solid "
    "#ddd"
    ";border-radius:8px;padding:12px 16px;flex:1}\n"
    ".card .n{font-size:28px;font-weight:700}.c{color:"
    "#b91c1c"
    "}.h{color:"
    "#b45309"
    "}.o{color:"
    "#15803d"
    "}\n"
    "table{border-collapse:collapse;width:100%;background:"
    "#fff"
    ";border-radius:8px;overflow:hidden}\n"
    "th,td{text-align:left;padding:8px 12px;border-bottom:1px solid "
    "#eee"
    ";font-size:13px}\n"
    "th{background:"
    "#f3f4f6"
    "}\n"
    "code{background:"
    "#f3f4f6"
    ";padding:1px 4px;border-radius:3px}"
)

HTML = '<!doctype html><html><head><meta charset="utf-8"><title>Ingress Exposure Report</title><style>' + CSS + '</style></head><body>'
HTML += '<h1>Ingress Exposure Scan Report</h1>'
HTML += '<p>{{ results | length }} endpoints scanned</p>'
HTML += '<div class="cards">'
HTML += '<div class="card"><div class="n c">{{ counts.no_auth }}</div><div>EXPOSED_NO_AUTH (CRITICAL)</div></div>'
HTML += '<div class="card"><div class="n h">{{ counts.default_creds }}</div><div>EXPOSED_DEFAULT_CREDS (HIGH)</div></div>'
HTML += '<div class="card"><div class="n o">{{ counts.protected }}</div><div>Protected</div></div>'
HTML += '</div>'
HTML += '<table><tr><th>Severity</th><th>Endpoint</th><th>Middleware</th><th>Status</th><th>Evidence</th></tr>'
HTML += '{% for r in results %}'
HTML += '<tr><td><span class="{{ r.severity.value }}">{{ r.severity.value }}</span></td>'
HTML += '<td><code>{{ r.target.url }}</code></td>'
HTML += '<td>{{ r.middleware or "-" }}</td>'
HTML += '<td>{{ r.auth_status.value }}</td>'
HTML += '<td>{{ "; ".join(r.evidence[:3]) }}</td></tr>'
HTML += '{% endfor %}</table></body></html>'

HTML_TEMPLATE = Template(HTML)


def render_html(results: list[ScanResult]) -> str:
    from collections import Counter
    counts = Counter(r.auth_status for r in results)
    return HTML_TEMPLATE.render(
        results=sorted(results, key=lambda r: SEVERITY_RANK[r.severity]),
        counts={
            "no_auth": counts.get(AuthStatus.EXPOSED_NO_AUTH, 0),
            "default_creds": counts.get(AuthStatus.EXPOSED_DEFAULT_CREDS, 0),
            "protected": counts.get(AuthStatus.PROTECTED, 0) + counts.get(AuthStatus.BASIC_AUTH_PROTECTED, 0),
        },
    )
