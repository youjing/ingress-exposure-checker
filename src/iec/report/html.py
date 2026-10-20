from iec.models import ScanResult, AuthStatus, SEVERITY_RANK
from jinja2 import Template

CSS = (
    "body{font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;"
    "margin:24px;background:"
    "#fafafa"
    ";color:#1f2937}\n"
    "h1{font-size:22px}h2{font-size:18px;margin-top:32px}h3{font-size:15px;margin:24px 0 8px}\n"
    "h4{font-size:14px;margin:20px 0 6px;color:#374151}\n"
    ".cards{display:flex;gap:12px;margin:16px 0}\n"
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
    ";border-radius:8px;overflow:hidden;margin:8px 0}\n"
    "th,td{text-align:left;padding:8px 12px;border-bottom:1px solid "
    "#eee"
    ";font-size:13px;vertical-align:top}\n"
    "th{background:"
    "#f3f4f6"
    ";white-space:nowrap}\n"
    "code{background:"
    "#f3f4f6"
    ";padding:1px 4px;border-radius:3px;font-size:12px}\n"
    ".sev-critical{color:"
    "#b91c1c"
    ";font-weight:700}.sev-high{color:"
    "#b45309"
    ";font-weight:700}\n"
    ".sev-info{color:"
    "#6b7280"
    "}.sev-ok{color:"
    "#15803d"
    "}\n"
    ".target-card{background:"
    "#fff"
    ";border:1px solid "
    "#e5e7eb"
    ";border-radius:8px;padding:12px 16px;margin:12px 0}\n"
    ".meta{color:"
    "#6b7280"
    ";font-size:13px;margin:4px 0}\n"
    ".meta b{color:"
    "#374151"
    "}\n"
    ".vuln{color:"
    "#b91c1c"
    ";font-weight:600}.safe{color:"
    "#15803d"
    "}\n"
    ".footer{color:"
    "#9ca3af"
    ";font-size:12px;margin-top:24px}\n"
    "a{color:"
    "#2563eb"
    ";text-decoration:none}\n"
    "a:hover{text-decoration:underline}"
)

# noqa: E501 - template lines are long by nature
HTML_TEMPLATE = Template("""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>Ingress 暴露面安全扫描报告</title>
<style>{{ css }}</style></head><body>
<h1>Ingress 暴露面安全扫描报告</h1>
<p>扫描目标总数:{{ results | length }}</p>
<div class="cards">
  <div class="card"><div class="n c">{{ counts.no_auth }}</div><div>严重 — 无需登录即可访问</div></div>
  <div class="card"><div class="n h">{{ counts.default_creds }}</div><div>高危 — 默认凭据可登录</div></div>
  <div class="card"><div class="n o">{{ counts.protected }}</div><div>正常 — 已有保护</div></div>
</div>

<h2>摘要</h2>
<table>
<tr><th>严重级别</th><th>可达性</th><th>命名空间</th><th>目标</th><th>中间件</th><th>状态</th><th>证据</th></tr>
{% for r in results %}
<tr>
<td><span class="sev-{{ r.severity.value }}">{{ r.severity_zh }}</span></td>
<td>{% if r.reachable %}<span class="safe">✅ 可达</span>{% else %}<span class="vuln">❌ 不可达</span>{% endif %}</td>
<td>{{ r.target.namespace or '-' }}</td>
<td><a href="{{ r.target.url }}" target="_blank" rel="noopener noreferrer">{{ r.target.url }}</a></td>
<td>{{ r.middleware or '-' }}</td>
<td>{{ r.status_zh }}</td>
<td>{{ r.evidence[:3] | join('; ') }}</td>
</tr>
{% endfor %}
</table>

<h2>详细测试报告</h2>
<p>按严重级别分组,展示每个目标的具体测试过程、请求/响应与结论。</p>
{% for group_name, group in detail_groups %}
<h3>{{ group_name }}({{ group | length }} 项)</h3>
{% for r in group %}
<div class="target-card">
<h4>[{{ r.target.namespace or '-' }} / {{ r.target.name or '-' }}]
  <a href="{{ r.target.url }}" target="_blank" rel="noopener noreferrer">{{ r.target.url }}</a></h4>
<p class="meta"><b>中间件:</b>{{ r.middleware or '未识别' }} &nbsp;&nbsp;
   <b>可达性:</b>{% if r.reachable %}<span class="safe">✅ 可达</span>{% else %}<span class="vuln">❌ 不可达</span>{% endif %} &nbsp;&nbsp;
   <b>判定:</b><span class="sev-{{ r.severity.value }}">{{ r.status_zh }}</span></p>
<p class="meta"><b>证据:</b>{{ r.evidence | join('; ') or '-' }}</p>
{% if r.error %}<p class="meta"><b>错误:</b>{{ r.error }}</p>{% endif %}
{% if r.details %}
<table>
<tr><th>测试项</th><th>测试说明</th><th>使用的凭据</th><th>请求</th><th>响应结果</th><th>结论</th></tr>
{% for d in r.details %}
<tr>
<td>{{ d.name }}</td>
<td>{{ d.description }}</td>
<td>{{ d.credentials }}</td>
<td>{{ d.request }}</td>
<td>{{ d.response }}</td>
<td>{% if d.vulnerable %}<span class="vuln">{{ d.result }}</span>{% else %}<span class="safe">{{ d.result }}</span>{% endif %}</td>
</tr>
{% endfor %}
</table>
{% else %}<p class="meta">_(无测试详情)_</p>{% endif %}
</div>
{% endfor %}
{% endfor %}
<p class="footer">本报告由 ingress-exposure-checker 自动生成;仅默认凭据检测,不含爆破。</p>
</body></html>""")


def render_html(results: list[ScanResult]) -> str:
    from collections import Counter

    counts = Counter(r.auth_status for r in results)
    groups = []
    for key, title in (("critical", "🔴 严重漏洞"), ("high", "🟠 高危漏洞"),
                       ("info", "⚪ 信息 / 待确认"), ("ok", "🟢 正常")):
        group = sorted(
            (r for r in results if r.severity.value == key),
            key=lambda r: r.target.namespace,
        )
        if group:
            groups.append((title, group))

    return HTML_TEMPLATE.render(
        css=CSS,
        results=sorted(results, key=lambda r: SEVERITY_RANK[r.severity]),
        counts={
            "no_auth": counts.get(AuthStatus.EXPOSED_NO_AUTH, 0),
            "default_creds": counts.get(AuthStatus.EXPOSED_DEFAULT_CREDS, 0),
            "protected": counts.get(AuthStatus.PROTECTED, 0)
                         + counts.get(AuthStatus.BASIC_AUTH_PROTECTED, 0),
        },
        detail_groups=groups,
    )
