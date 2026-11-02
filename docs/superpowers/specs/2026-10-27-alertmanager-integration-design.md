# Alertmanager 告警推送集成 — 设计文档

日期:2026-10-27
状态:已批准

## 1. 背景与目标

iec 已有 Slack 通知出口(webhook 卡片 + token 上传报告)。新增对 **Prometheus Alertmanager** 的直推能力,使告警进入现有告警路由(钉钉/企微/邮件/oncall),并获得**告警生命周期管理**:跨扫描去重、漏洞修复后自动 resolved。

选型结论:直推 `POST /api/v2/alerts`(方案 A);否决 metrics 方案(基础设施耦合重)与通知分发器抽象(仅两个出口,过早设计)。

## 2. 需求决定

| 决策点 | 结论 |
|---|---|
| 告警粒度 | **每漏洞一条**(instance=URL,跨扫描去重,单条可独立 resolved) |
| 认证 | HTTP Basic Auth(用户名/密码均可选,无密码 AM 不传) |
| 发送范围 | 仅严重/高危(与 Slack 一致) |
| 生命周期 | `endsAt = now + 25h`(默认,适配每日 CronJob),防间歇扫描被 resolve_timeout 自动关闭 |

## 3. 设计

### CLI 参数

```
--alertmanager-url URL           # AM base(可含反代前缀,自动补 /api/v2/alerts)
--alertmanager-user USER         # 可选
--alertmanager-password PW       # 可选
--alertmanager-endsat-hours N    # 默认 25
```

TLS 校验复用 `--insecure-tls`。凭据仅命令行传入,不入仓。

### 告警格式

```json
[{
  "labels": {
    "alertname": "IngressExposure",
    "severity": "critical | high",
    "instance": "<完整目标 URL>",
    "namespace": "<ingress 命名空间>",
    "middleware": "<识别的中间件>",
    "env": "<环境名>"
  },
  "annotations": {
    "summary": "<中文状态描述>",
    "description": "<证据; 若存在漏洞凭据则前置 [凭据: user/pass]>"
  },
  "startsAt": "<扫描完成时间 RFC3339>",
  "endsAt": "<startsAt + 25h>"
}]
```

排序:严重在前、高危在后、同级别按 namespace。环境名复用 Slack 的
`env_name_from_file`(`.ingress.txt` 前缀)。

### 模块与数据流

```
src/iec/report/alertmanager.py
  build_alerts(results, env_name, ends_hours) -> list[dict]
  send_to_alertmanager(url, alerts, user, password, verify_tls) -> (ok, msg)
cli.py: 报告生成后, 若 --alertmanager-url 提供则构建并 POST
```

- 成功 = HTTP 200;失败(非 200/网络错误)打印 `✗ Alertmanager: 原因`
- 发送失败不阻断报告生成与退出码(与 Slack 同语义)
- 0 条告警时不发请求

## 4. 测试

respx mock `/api/v2/alerts`:
1. 仅 critical/high 被发送(PROTECTED/UNKNOWN 排除)
2. labels 五字段 + annotations 断言;漏洞凭据前置于 description
3. Basic Auth 请求头断言(提供 user/pass 时);无密码场景无 auth
4. endsAt ≈ startsAt + 25h
5. 非 200 失败路径
6. 0 告警时路由未被调用

## 5. 安全边界

凭据(Webhook/Token/AM 密码)一律仅命令行传入;README 示例全占位符;
测试全虚构数据;提交前执行脱敏 grep(公司域名/真实凭据)。
