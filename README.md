# global-cf-auto

全球 Cloudflare 自动化工具（global-cf-auto）

一个用于从CF读取域名并检测到期时间，以及批量管理 Cloudflare Zone、导出 DNS、以及通过 Telegram 接收/触发操作的轻量级工具。适用于需要集中管理多个 Cloudflare 账号并通过机器人快速执行常用运维任务的场景。

**主要功能**

- 基于本地资产缓存监控域名续费到期、当前 HTTPS 访问 SSL 证书到期，并在到期前提醒。证书到期判断通过 TLS 握手读取站点当前返回的证书链，不调用 Cloudflare Origin CA 列表 API。
- 每日扫描 Cloudflare 滥用报告，发现新报告后发送一次 Telegram 通知，并通过本地缓存去重，避免重复提醒。
- 通过 Telegram Bot 提供交互式命令：查询 DNS、添加域名、查看 NS、设置解析、删除域名、导出 CSV。
- 支持将 DNS 导出为 CSV（按账号/Zone/记录分行）。
- 内置 Cloudflare API 抽象（`cfclient`），方便替换为测试假实现。

**仓库结构（精简）**

- `main.go`：程序入口，初始化组件并启动监听。
- `config/`：配置加载与结构定义，读取 `config.yaml`。
- `cfclient/`：Cloudflare 客户端抽象与实现，提供 `Client` 接口。
- `internal/app/`：核心业务逻辑（通知、收集器、检查器等）。
- `telegram/`：Telegram 相关的 Sender、命令处理与导出逻辑。
- `callback/`：Telegram 回调处理（按钮交互）。
- `domain/`：域名仓库与管理辅助。
- `scheduler/`：调度逻辑（定期任务触发）。
- `tools/`：工具函数与小脚本。

**主要文件**

- 配置示例：`config.yaml`
- Telegram 命令处理：`telegram/commands.go` 和分割的命令文件（`dns_command.go`, `getns_command.go`, `setdns_command.go`, `status_command.go`, `delete_command.go`, `csv_command.go`）
- Cloudflare 抽象：`cfclient/client.go`

**配置（快速开始）**

1. 复制并编辑 `config.yaml`，至少设置 Telegram Bot Token 与 Cloudflare 账号：

```yaml
# 示例（需按实际填写）
telegram:
	token: "<BOT_TOKEN>"
	chat_id: 123456789

cloudflare_accounts:
	- label: "acc1"
		api_token: "<CF_API_TOKEN>"
```

2. 可选：将 `aws.txt` / `expiring_domains.txt` 用作导入或记录。

**运行**

构建并运行：

```bash
go build ./...
./global-cf-auto
```

程序会初始化 Cloudflare 客户端、Telegram Sender，并在配置的群组/私聊中监听命令与回调。


**域名与 SSL 到期提醒**

- 默认到期前 7 天提醒，可通过 `alertDays` 调整。
- 缓存文件默认 `domain_asset_cache.json`，可通过 `assetCacheFile` 指定。
- 程序每次启动后会异步执行一次 Cloudflare 域名基线同步：慢速读取所有当前有权限账号下的 Zone 清单，与本地缓存增量对比。已有缓存不会被清空或重建，原有续费时间、证书时间会保留；Cloudflare 新发现但本地没有的域名会自动加入缓存并进入后台补全队列；本地缓存里存在但当前有权限账号已读不到的 Cloudflare 域名不会直接删除，会在对应账户归属上标记为“未知账户”，便于在日报 CSV 中人工确认。
- 启动同步只在本次进程启动后执行一次，后续运行期仍以用户命令新增/删除域名来维护缓存。
- 启动同步和后续命令写入缓存时，缓存主键按“域名”去重；如果多个账户平台都存在同一个域名，会合并成一条资产记录，并在 `sources` / `accounts` 中记录多个账户归属，避免日报重复展示。
- `/getns` 新增或识别域名后，会自动写入资产缓存并异步补全域名续费时间和当前 HTTPS/443 访问证书。
- `/delete` 删除 Cloudflare Zone 成功后，会自动更新资产缓存；如果同一个域名仍属于其他账户，只移除本次删除的账户归属，不会删除整条域名资产。
- `/ssl` 创建 Cloudflare Origin CA 证书成功后，证书文件仍会正常返回；到期提醒模块不再依赖 Cloudflare Origin CA 查询接口，而是以后续 HTTPS 访问实际返回的证书为准。
- SSL 证书刷新只检查 `domain:443` TLS 握手返回的当前访问证书；如果域名没有解析、没有开放 443 或只作为 DNS Zone 使用，会在刷新错误中记录访问证书读取失败，但不会再出现 Cloudflare Origin CA 平台 API 权限错误。
- 每日 15:00 执行一次提醒任务：优先直接基于本地资产缓存计算并发送 Telegram 摘要和附件，避免 RDAP/WHOIS/TLS 批量刷新阻塞日报。报告发送成功后，才会把确实需要补全或超过刷新 TTL 的资产放入后台慢速刷新队列；已有有效续费时间的域名默认不会每天重复查询，到期时间默认 7 天刷新一次，临近到期资源最多每天刷新一次用于识别续费后的变化。
- 每日 Telegram 都会发送一条摘要：如果当天没有临近到期/已到期资源，会明确提示“今日没有域名续费或 SSL 证书到期资源”，并汇总当前缓存唯一域名总数、账户归属数、多账户域名数、SSL 证书记录数、每个账户平台下的域名数量；如果有，则合并显示域名续费到期数量、SSL 证书到期数量和总数。
- 每日摘要会附带报表文件：无到期资源时默认发送 CSV 全量资产表，适合域名数量较多时下载筛选；有到期资源时默认优先发送 HTML 表格附件，便于手机或浏览器直接查看，如果 HTML 生成失败会自动降级为 CSV。报表中的“账户平台”会合并展示同一域名所属的多个账户，“账户数”用于快速判断是否为多账户域名。
- 报表字段包含账户平台、域名、资源类型、资源名称、到期时间、剩余时间、状态、证书类型、证书 ID、签发方、证书主体、证书域名、最后刷新时间和刷新错误，便于按账号平台定位排查。

配置示例：

```yaml
alertDays: 7
assetCacheFile: "domain_asset_cache.json"
```


**Cloudflare 滥用报告提醒**

- 默认启用，每天定时扫描一次所有配置的 Cloudflare 账号。
- 默认扫描时间为 15:30，避免和 15:00 的域名/SSL 到期日报互相阻塞。
- 每个滥用报告按 `账号 + 报告ID` 去重；如果接口没有返回报告 ID，会基于账号、域名、报告类型、日期、摘要、URL 生成稳定哈希。
- 只有新发现且未通知过的报告才会发送 Telegram，已通知过的报告即使仍处于活动状态也不会重复通知。
- Telegram 消息会使用“小白可读”的方式输出：先说明这不是程序错误，而是 Cloudflare 收到针对域名的投诉/举报；再按风险、账号、报告类型汇总，并对重点报告给出白话说明、可能原因和建议处理动作。
- 报告类型会自动翻译，例如 `GEN` 会展示为“通用滥用报告（GEN）”，`accepted` 会展示为“Cloudflare 已受理/接受”；如果 Cloudflare 返回了缓解动作，会说明这些动作是否处于活动中。
- 新报告较多时，消息正文只展示前 5 条重点解读，完整清单会附带 HTML 报告文件。HTML 报告包含统计卡片、按账号/类型汇总、每条报告的风险等级、原因概述、建议处理、证据 URL、原始摘要和 Cloudflare 原始字段，便于一眼判断是什么原因导致。
- 如果 HTML 生成失败，会自动降级为 CSV 附件；本地去重缓存默认 `abuse_report_cache.json`，可通过配置修改。

配置示例：

```yaml
abuseReport:
  enabled: true
  cacheFile: "abuse_report_cache.json"
  scanHour: 15
  scanMinute: 30
  perPage: 50
  maxPages: 5
```

环境变量覆盖：

```bash
ABUSE_REPORT_ENABLED=true
ABUSE_REPORT_CACHE_FILE=abuse_report_cache.json
```

**Telegram 命令（机器人支持）**

- `/dns <domain.com>`：列出域名的 DNS 记录。
- `/getns <domain.com>`：查询域名是否存在，若不存在则尝试创建 zone 并返回 NS。
- `/status <domain.com>`：查看 Zone 状态（是否 paused）并显示操作人。
- `/delete <domain.com>`：触发删除确认，会发送带按钮的确认消息。
- `/setdns <domain> <type> <name> <content> [proxied] [ttl]`：创建或更新解析记录。
- `/csv <label|all>`：导出指定账号或全部账号的 DNS 为 CSV 并发送文件。
- `/cf_rules <label> all feature=sql` 或 `/cf_rules <label> all sql`：给指定 Cloudflare 账号下所有域名开启/更新 SQL 注入拦截 WAF 自定义规则。
- `/cf_rules all sql`：给配置中的全部 Cloudflare 账号、全部域名开启/更新 SQL 注入拦截规则；`/cf_rules all sql action=disable` 可删除该规则。
- `/originssl domain.com *`：生成源站15年的ssl证书,host 为domain.com 和  *.domain.com

**开发与测试**

- 运行所有测试：

```bash
go test ./...
```

- 本项目对 Cloudflare 操作使用 `cfclient.Client` 接口，测试中常用 fake 实现（见 `internal/app/notifier_test.go`）。

**扩展建议**

- 将 Telegram 发送器的实现抽离为可插拔模块（便于本地/远程部署）。
- 在 `csv` 导出中支持更多字段和过滤（按类型、TTL、是否代理）。
- 为长运行命令添加进度反馈与限流控制。
- 将查询的到期时间缓存起来，到期前不用再次查询，提高效率
- 将无法查询到的域名统一报出来

**SQL 注入拦截规则说明**

`/cf_rules ... sql` 会在每个 Zone 的 `http_request_firewall_custom` 入口规则集中创建或升级描述为 `telegram-auto-sqli-block` 的 Block 规则。规则优先安装“query + body”版本，覆盖 URL query、原始请求体、表单字段值、multipart 字段值中的 `sleep()`、`benchmark()`、`pg_sleep()`、`waitfor delay`、`information_schema`、`performance_schema`、`ord()`、`mid()`、`substring()`、`find_in_set()` 等时间盲注/结构枚举特征；如果当前 Zone 套餐不支持正则匹配，会自动回退到 `contains` 兼容表达式；如果当前套餐或权限不支持 Cloudflare 请求体字段，会继续降级为 query-only 版本，并在执行结果中显示 `query_only_regex` 或 `query_only_contains`。

SQL 拦截结果状态后缀说明：`query_body_regex` 表示已覆盖 URL query + request body 且使用正则；`query_body_contains` 表示已覆盖 URL query + request body 但使用兼容 contains；`query_only_regex` / `query_only_contains` 表示 Cloudflare 不接受请求体字段或正则能力不足，只安装了 URL query 版本。
