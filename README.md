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
| PROTECTED | 有登录，默认凭据全部失败 | OK |
| BASIC_AUTH_PROTECTED | HTTP Basic 认证挑战 | OK |
| UNKNOWN | 未知应用，仅报告观察信号 | INFO |

## 支持的中间件

Grafana, RabbitMQ Management, Nacos, Elasticsearch, Prometheus, Alertmanager,
Logstash, Harbor, Nexus, MinIO, phpMyAdmin, Tomcat Manager, Mongo Express,
Druid, Kafka UI, phpinfo, Kibana, Jenkins, JFrog Artifactory, ChirpStack (v3/v4)。

新增中间件：在 `src/iec/plugins/` 添加一个 `MiddlewarePlugin` 子类并用 `@register` 装饰即可。
