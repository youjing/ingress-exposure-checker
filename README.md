# ingress-exposure-checker (`iec`)

扫描公网暴露的 Ingress endpoint，检测无鉴权访问与默认凭据漏洞。

## 安装

**uv (推荐, 自动管理 Python 版本):**

```bash
uv tool install git+https://github.com/youjing/ingress-exposure-checker.git
```

**pipx:**

```bash
pipx install git+https://github.com/youjing/ingress-exposure-checker.git
```

**开发模式:**

```bash
git clone git@github.com:youjing/ingress-exposure-checker.git
cd ingress-exposure-checker
pip install -e ".[dev]"
```

**Docker:**

```bash
docker build -t iec .
docker run --rm -v "$PWD/output:/scan/output" iec \
    <targets-file> --authorized --output-html /scan/output/report.html \
    --output-md /scan/output/report.md
```

> 目标文件也需挂载进容器或在容器内路径可达。

升级: `uv tool upgrade ingress-exposure-checker`

## 使用

准备目标文件。支持三种格式:

1. 纯文本（每行一个 URL）:

```
http://grafana.example.com
https://nacos.internal.example.com/nacos
```

2. CSV（表头须含 `url` 列, `name` 列可选）:

```
name,url
grafana-prod,http://grafana.example.com
```

3. **Ingress 导出表**（`kubectl get ing -A -o wide` 输出, 参见 `list-ingress.sh`）:
   自动识别 NAMESPACE/NAME/HOSTS/PATHS/PORTS 列, 443 端口优先 https, 并在报告中携带命名空间。

运行:

```bash
# 批量扫描
iec targets.txt --authorized --output-html report.html --output-md report.md --insecure-tls

# 单个 URL 快速验证, 结果仅输出到终端
iec --url "https://target.example.com/kibana" --authorized --no-report --insecure-tls

# 绕过系统代理直连探测（判定反映本机真实网络路径）
iec targets.txt --authorized --direct --insecure-tls
```

> `--authorized` 为必填项，声明你对目标拥有测试授权。

常用参数: `--concurrency`（并发, 默认 20）、`--timeout`（超时, 默认 10s）、
`--direct`（绕过系统代理）、`--insecure-tls`（跳过证书校验）、`--no-report`（仅终端输出）。

## 报告

- 终端实时输出（rich, 含详细测试过程）
- HTML 自包含单文件报告（URL 可点击, 可直接分发给团队）
- Markdown 报告

报告按严重级别分组, 每个目标展示测试项、使用的凭据、请求与响应、结论。

## 风险分级

| 状态 | 含义 | 级别 |
|---|---|---|
| EXPOSED_NO_AUTH | 控制台/敏感 API/API 文档无需登录直接可访问 | CRITICAL |
| EXPOSED_DEFAULT_CREDS | 有登录，默认凭据可登录 | HIGH |
| PROTECTED | 有登录，默认凭据全部失败 | OK |
| BASIC_AUTH_PROTECTED | HTTP Basic 认证挑战 | OK |
| UNKNOWN | 未知应用，仅报告观察信号 | INFO |

仅默认凭据检测（每个目标 ≤5 组已知默认口令），不做爆破，不会触发账号锁定。

## 支持的中间件

Grafana, RabbitMQ Management, Nacos, Elasticsearch, Prometheus, Alertmanager,
Logstash, Harbor, Nexus, MinIO, phpMyAdmin, Tomcat Manager, Mongo Express,
Druid, Kafka UI, phpinfo, Kibana, Jenkins, JFrog Artifactory, ChirpStack (v3/v4),
Swagger/OpenAPI, Spring Boot Actuator。

对指纹无法识别的目标, 会自动通用探测常见 API 文档路径(swagger.json / v3/api-docs / actuator 等)。

新增中间件：在 `src/iec/plugins/` 添加一个 `MiddlewarePlugin` 子类并用 `@register` 装饰即可。

## 安全说明

- 仅用于对**自有/已授权资产**的安全审计, 工具强制 `--authorized` 门禁
- 请求头带明确扫描器标识 `ingress-exposure-checker`, 不伪装
- 默认凭据测试前先做控制组校验, 避免误报

## CI

GitHub Actions 在 push/PR 时自动跑测试并构建 wheel/sdist 产物;
打 `v*` tag 会自动创建 Release 并附上构建包。
