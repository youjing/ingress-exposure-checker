# Ingress 暴露面安全扫描工具 — 设计文档

日期:2026-10-12
状态:已批准(用户确认)

## 1. 背景与目标

团队有大量 Kubernetes Ingress 暴露到公网的 endpoint。需要一个内部安全审计工具,对这些 endpoint 做:

1. **指纹识别**:判断 endpoint 背后部署的是什么中间件(如 Grafana、RabbitMQ Management、Elasticsearch 等)
2. **鉴权状态判定**:判断哪些无密码保护、哪些有登录但仍在使用默认凭据
3. **默认凭据检测**:用每个中间件的已知默认凭据做少量试探(非爆破)
4. **报告生成**:输出漏洞报告,含风险等级、证据、修复建议

**适用范围**:仅用于对自有/已授权资产的安全审计。工具内置授权确认门禁,防止误扫第三方。

## 2. 需求决定(澄清结论)

| 决策点 | 结论 |
|---|---|
| 输入来源 | 文件导入(TXT/CSV),工具不直接访问 K8s API |
| 扫描规模 | 几十到几百个 endpoint,简单异步并发即可 |
| 中间件范围 | 监控/消息类、DevOps 工具类、数据库/管理类全覆盖,尽可能多识别;额外指定 Elasticsearch、Redis(Web UI)、Logstash、JFrog、Kafka(UI)、Alertmanager |
| 密码试探强度 | 仅已知默认凭据(每目标 ≤5 组合),不做字典爆破 |
| 报告格式 | HTML 交互报告 + Markdown + 终端实时输出 |
| 技术栈 | Python 3.12,httpx 异步,uv 管理 |
| 未知目标判定 | 已知/未知两套判定:未知目标只报告观察信号,不下"无鉴权"结论 |

## 3. 方案选择

**选定:插件式检测引擎(方案 A)**。

- 核心框架 = HTTP 异步抓取(httpx)+ 指纹引擎 + 凭据测试引擎 + 插件注册表
- 每个中间件是一个插件:指纹规则 + 检测流程定义
- 新增中间件只需增加一份插件,核心逻辑零改动
- 纯 Python,无外部二进制依赖

否决的替代方案:
- 单体流水线脚本:每加中间件都要改核心代码,难维护
- nuclei 模板 + Python 包装:表单登录流程定制是 nuclei 弱项,且引入外部依赖

## 4. 架构

```
ingress_exposure_checker/
├── pyproject.toml              # uv 管理,Python 3.12
├── docs/superpowers/specs/     # 设计文档
├── src/iec/
│   ├── cli.py                  # CLI 入口
│   ├── input.py                # 解析 TXT/CSV → Target 列表(去重/规范化)
│   ├── http.py                 # httpx 异步客户端封装(并发/限速/超时)
│   ├── fingerprint.py          # 指纹引擎(规则注册表)
│   ├── credcheck.py            # 凭据测试引擎(表单/Basic/API 三类流程)
│   ├── models.py               # Target / ScanResult / AuthStatus / Severity
│   ├── report/
│   │   ├── terminal.py         # rich 实时输出
│   │   ├── html.py             # Jinja2 自包含单文件 HTML
│   │   └── markdown.py         # Markdown 报告
│   └── plugins/
│       ├── base.py             # MiddlewarePlugin 基类 + 注册表
│       └── <middleware>.py     # 每个中间件一个插件
└── tests/
    ├── unit/                   # 指纹规则、判定逻辑、输入解析
    └── e2e/                    # CLI 端到端(respx mock HTTP)
```

### 组件职责

| 组件 | 职责 | 依赖 |
|---|---|---|
| cli.py | 参数解析、授权门禁、编排扫描与报告 | 全部 |
| input.py | 读取 TXT(每行一个 URL)/ CSV(name,url 列),规范化(scheme 补全、去重、仅 http/https) | models |
| http.py | 共享 AsyncClient;全局并发信号量(默认 20)、单主机信号量(默认 2)、超时 10s | — |
| fingerprint.py | 按规则序匹配:HTTP headers(Server/X-Powered-By/Set-Cookie 名)、HTML 特征(title/正文标记)、favicon mmh3 hash、特征 API 路径响应;输出 MiddlewareType + 置信度 + 证据 | http, plugins |
| credcheck.py | 三类检测流程:① 表单登录(POST 字段 + 成功判定:重定向/cookie/响应体特征)② Basic Auth ③ API 未授权探测(直接请求敏感端点) | http, plugins |
| report/* | 渲染三种格式报告 | models |

## 5. 检测流程与判定分类

```
输入文件 → 解析/去重/规范化 URL → 异步并发扫描
  ├─ 阶段1: 可达性 + 指纹识别 (GET /、favicon、特征路径、headers)
  ├─ 阶段2: 按指纹分派
  │    ├─ 已知中间件 → 对应插件:未授权探测 或 默认凭据测试
  │    └─ 未知 → 仅记录通用信号(401 Basic 挑战?登录页特征?裸 200?)
  └─ 聚合 → 终端实时输出 + HTML/Markdown 报告
```

### AuthStatus 判定

| 状态 | 含义 | 风险级 |
|---|---|---|
| `EXPOSED_NO_AUTH` | 控制台/敏感 API 无需登录直接可访问 | CRITICAL |
| `EXPOSED_DEFAULT_CREDS` | 有登录,默认凭据可登录 | HIGH |
| `PROTECTED` | 有登录,默认凭据全部失败 | OK |
| `BASIC_AUTH_PROTECTED` | HTTP Basic 认证挑战(未试探) | OK |
| `UNKNOWN` | 未知应用,仅报告观察信号 | INFO |
| `INCONCLUSIVE` | 判定特征不可靠(控制组异常) | INFO |
| `UNREACHABLE` / `ERROR` | 不可达 / 请求异常 | — |

### 防误报:控制组机制

默认凭据测试前,先提交一组**错误凭据**验证"失败特征"确实可靠(如返回 401、重定向回登录页)。控制组表现与插件定义不符 → 标记 `INCONCLUSIVE`,不尝试默认凭据、不下结论。

## 6. v1 插件清单

### 默认凭据类(表单/Basic 登录)

| 中间件 | 默认凭据(示例) | 登录方式 |
|---|---|---|
| Grafana | admin/admin | 表单,成功判定:API `GET /api/user` 返回 isGrafanaAdmin |
| RabbitMQ Management | guest/guest | 表单 |
| Nacos | nacos/nacos | 表单 + **未开鉴权检测**(API 直接返回数据) |
| Harbor | admin/Harbor12345 | API 登录 |
| Nexus | admin/admin123 | API(老版本) |
| MinIO Console | minioadmin/minioadmin | API 登录 |
| phpMyAdmin | root/(空密码)、root/root | 表单(含 token) |
| Tomcat Manager | tomcat/tomcat | Basic Auth |
| Mongo Express | 无密码、admin/pass | Basic Auth |
| JFrog Artifactory | admin/password | 表单/API |

### 未授权访问类(API 型,无登录界面)

| 服务 | 探测端点 |
|---|---|
| Elasticsearch | `GET /_cluster/health`、`/_cat/indices` |
| Prometheus | `GET /api/v1/status/buildinfo` |
| Alertmanager | `GET /api/v2/status` |
| Logstash | `GET /_node/stats` |
| Druid Monitor | `GET /druid/index.html` |
| Kafka UI (provectus 等) | 首页直接可访问(无登录跳转) |
| phpinfo | 特征页指纹 |
| Redis Web UI (redis-commander 等) | 首页直接可访问 |

### 特殊处理

- **Kibana / Jenkins**:无公开默认凭据,仅检测"未授权直接进入控制台"
- **Redis / Kafka / Logstash**:核心是 TCP 协议或纯 API,经 Ingress 暴露的实际是 Web UI 或 HTTP API,按上表对应插件检测
- 识别到中间件但探测流程无法执行时,报告指纹结果 + `INCONCLUSIVE`

## 7. 安全边界(工具自身防护)

1. **授权门禁**:CLI 必须显式传 `--authorized` 才运行,否则打印授权声明并退出
2. **仅默认凭据**:每目标 ≤5 个组合,首个成功即停;不重试、不爆破、不读大字典
3. **限速**:全局并发默认 20,单主机并发默认 2,请求超时 10s(均可通过 CLI 调整)
4. **明示扫描身份**:User-Agent = `ingress-exposure-checker/0.1 (internal audit)`,不伪装
5. 报告与日志**不落盘** session cookie 等敏感凭据证据;默认凭据组合本身是公开知识,可展示

## 8. 错误处理

- 单目标超时 / 连接失败 → `UNREACHABLE`;其他异常 → `ERROR`;均不中断全局扫描
- TLS 证书错误:默认**验证**证书;`--insecure-tls` 允许跳过(内部中间件自签名常见)
- 指纹置信度低于阈值 → `UNKNOWN`,不强行归类
- 输入校验:仅接受 `http://` / `https://` URL(无 scheme 默认补 `http://`,可配置)

## 9. 测试策略

- **单元测试**(pytest):
  - 指纹规则:fixture HTML/headers/favicon 驱动,覆盖每插件正/反例
  - 凭据判定:respx mock HTTP,覆盖成功/失败/控制组异常/INCONCLUSIVE 路径
  - 输入解析:格式边界、去重、scheme 规范化
- **CLI 端到端**:黄金样例输入文件 + respx mock,断言终端输出与 HTML/Markdown 报告内容
- 真实中间件 docker 集成测试为可选目录(`tests/integration/`),不进默认测试流程

## 10. 报告内容规格

- **终端**(rich):扫描进度条、发现即打印(CRITICAL/HIGH 高亮)、结束汇总表
- **HTML**(自包含单文件,可邮件/IM 分发):
  - 概览卡片:扫描总数、可识别数、EXPOSED_NO_AUTH 数、EXPOSED_DEFAULT_CREDS 数、风险分布
  - 明细表:按风险级排序,支持按状态筛选;每行含 endpoint、中间件+版本、判定状态、证据摘要、修复建议
- **Markdown**:摘要表 + 明细列表,适合贴内部文档/PR
- 修复建议:按中间件内置(如"修改默认密码""开启 Nacos 鉴权 nacos.core.auth.enabled=true""给 ES 启用 xpack.security")
