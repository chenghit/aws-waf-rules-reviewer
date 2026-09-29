## Issue 1 (Critical): probe_service_pass_2 / probe_service_pass 基于可伪造条件实现全局 Allow 绕过

**Rules**: probe_service_pass_2 (priority 4), probe_service_pass (priority 17)
**Current state**: single_header:x-detect-header EXACTLY 'cloud-detect-16TNBPz9L00rabcdefgh'，action 为 Allow，无 scope-down

**Problem**:
- single_header:x-detect-header 是完全可伪造的，攻击者只需在请求中添加匹配的自定义请求头即可绕过所有后续规则（包括 IP 信誉、Bot Control、速率限制等）
- 该规则的 blast radius 是全局的：所有路径都受影响，没有 host 或 URI 限制
- 匹配值 `cloud-detect-16TNBPz9L00rabcde...` 存储在 WAF 配置中，任何能读取 Web ACL 配置的人都能拿到，一旦泄露就能完全绕过 WAF

**Recommendation**:
- 将 action 改为 Count+Label（如 `custom:native-app` 或 `custom:probe`），不要直接 Allow，这些流量不需要绕过 WAF
- 如果此规则用于内部探针或监控工具，应改用不可伪造的条件（如 IP Set 或 WAF Token）
- 定期轮换密钥值，并审计 WAF 配置的 IAM 访问权限

---
## Issue 2 (Critical): APP-BYPASS_2 / APP-BYPASS 基于可伪造条件实现全局 Allow 绕过

**Rules**: APP-BYPASS_2 (priority 8), APP-BYPASS (priority 19)
**Current state**: single_header:user-agent STARTS_WITH 'example'，action 为 Allow，无 scope-down

**Problem**:
- single_header:user-agent 是完全可伪造的，攻击者只需在请求中添加匹配的 User-Agent 头即可绕过所有后续规则（包括 IP 信誉、Bot Control、速率限制等）
- 该规则的 blast radius 是全局的：所有路径都受影响，没有 host 或 URI 限制

**Recommendation**:
- 将 action 改为 Count+Label（如 `custom:native-app` 或 `custom:probe`），不要直接 Allow，这些流量不需要绕过 WAF
- 如果此规则用于内部探针或监控工具，应改用不可伪造的条件（如 IP Set 或 WAF Token）

---
## Issue 3 (Medium): AntiDDoS AMR 的豁免 URI 正则表达式未锚定，攻击者可利用路径注入绕过

**Rule**: AWS-AWSManagedRulesAntiDDoSRuleSet (priority 0)
**Current state**: 豁免正则 `\/query|\/models|\/messages|\/balance|\/completions|\/api\/|\.(acc|avi|css|gif|ico|jpe?g|js|json|mp[34]|ogg|otf|pdf|png|tiff?|ttf|webm|webp|woff2?|xml|svg)$`，API 路径分支未使用 `^` 锚定

**Problem**:
- 以下正则分支未以 `^` 锚定，意味着它们是"包含"匹配而非"以...开头"匹配：`\/query`, `\/models`, `\/messages`, `\/balance`, `\/completions`, `\/api\/`
- 攻击者可以构造包含这些关键词的任意路径，让 `ChallengeDDoSRequests` 跳过这些请求，例如：`/admin/query/export`, `/admin/models/export`
- 这使得攻击者可以通过精心构造的路径，让攻击请求被豁免于 Challenge

**Recommendation**:
- 为所有 API 路径分支添加 `^` 锚定：`^\/query|^\/models|^\/messages|^\/balance|^\/completions|^\/api\/|\.(acc|avi|css|gif|ico|jpe?g|js|json|mp[34]|ogg|otf|pdf|png|tiff?|ttf|webm|webp|woff2?|xml|svg)$`
- 先确认真实路径。如果 API 挂在 `/v1/` 这样的前缀下，要连前缀一起锚定（`^\/v1\/query`），否则加了 `^` 的分支就匹配不上了
- 静态资源后缀匹配已正确使用 `$` 锚定，无需修改

---
## Issue 4 (Medium): Challenge 规则作用于 API/POST 路径，实际效果等同于 Block

**Rules**: challenge-all-reasonable-specific_path_2 (priority 2), platform_create_payment_bot_control (priority 13), challenge-all-reasonable-specific_path (priority 15), platform_create_payment_bot_control_2 (priority 24)
**Current state**: 对 API 路径和/或 POST 请求应用 Challenge action

**Problem**:
- Challenge 只能由浏览器 GET 请求完成（需要执行 JavaScript 并接受 HTML 响应）
- API 路径通常由原生 App 或 JavaScript fetch/XHR 访问，无法完成 Challenge
- POST 请求无法完成 Challenge：客户端会收到 HTTP 202 但无法重新提交原始 POST 请求
- 实际效果：这些规则对 API 客户端和原生 App 等同于 Block

**Recommendation**:
- 对 API 滥用防护：考虑改用速率限制（rate-based rule）而非 Challenge
- 对 POST 端点：应在对应的 GET 页面（landing page）上应用 Challenge，而不是在 POST 请求上

---
## Issue 5 (Medium): IP 信誉和匿名 IP 规则组的 scope-down 过窄，仅检查首页

**Rules**: AWS-AWSManagedRulesAmazonIpReputationList (priority 5), AWS-AWSManagedRulesAnonymousIpList (priority 6)
**Current state**: scope-down 为 `uri_path EXACTLY '/'`，仅对首页路径生效

**Problem**:
- 两个规则组实际上只对 `GET /` 请求生效，所有其他路径（`/api/*`、`/login`、`/signup` 等）均不受 IP 信誉检查保护
- 恶意 IP 只需访问任何非首页路径即可完全绕过这两个规则组
- 这使得 IP 信誉保护形同虚设，尤其对 API 路径的攻击毫无防护

**Recommendation**:
- 移除这两个规则组的 scope-down，让其检查所有流量
- 如果出于性能或成本考虑需要限制范围，至少应覆盖所有关键路径，而不是仅限于首页

---
## Issue 6 (Medium): HostingProviderIPList 被覆盖为 Allow，云主机流量会跳过所有后续规则

**Rule**: AWS-AWSManagedRulesAnonymousIpList (priority 6)
**Current state**: `HostingProviderIPList` 规则被覆盖为 Allow，规则组的 scope-down 为 `uri_path EXACTLY '/'`

**Problem**:
- `HostingProviderIPList` 默认 Block 云托管和 Web 托管提供商的 IP。覆盖为 Allow 后，来自这些 IP 的请求直接放行，后面的规则都不再检查
- 现代 DDoS 攻击大量使用云托管基础设施（VPS、云函数、容器）。Allow 覆盖让这些攻击流量完全绕过 IP 信誉、Bot Control、速率限制等所有保护
- 正确做法是覆盖为 Count（保留标签，供下游规则使用），而非 Allow
- 规则组的 scope-down 是 `uri_path EXACTLY '/'`，只有匹配它的请求才会进入规则组。所以被放行的是匹配这个 scope-down 的云主机请求
- 要去掉或放宽这个 scope-down，先改掉这个 override，否则放行范围会跟着扩大

**Recommendation**:
- 将 `HostingProviderIPList` 的覆盖从 Allow 改为 Count
- 如果担心企业用户通过云代理访问时被误封，Count 模式已经解决了这个问题（不会 Block，只添加标签）

---
## Issue 7 (Medium): 规则顺序问题，发现 2 处

**Rules**: ban_chat_ipv6_2 (priority 9), ban_chat_ipv6 (priority 20)
**Current state**: 现有规则的评估顺序，影响到了哪些请求会被检查或拦截

**Problem**:
- IP 黑名单 `ban_chat_ipv6_2`（priority 9）排在 Allow 规则 `probe_service_pass_2`、`APP-BYPASS_2` 后面。被这些规则放行的请求不会再经过黑名单，已经拉黑的 IP 只要同时命中这些 Allow 规则，就会被放行
- IP 黑名单 `ban_chat_ipv6`（priority 20）排在 Allow 规则 `probe_service_pass_2`、`APP-BYPASS_2`、`probe_service_pass`、`APP-BYPASS` 后面。被这些规则放行的请求不会再经过黑名单，已经拉黑的 IP 只要同时命中这些 Allow 规则，就会被放行

**Recommendation**:
- 把 IP 黑名单调到所有 Allow 规则前面
- 新增规则类型时放在哪个位置，参考附录 D

---
## Issue 8 (Medium): Bot Control 跑的是旧版本，识别能力弱很多

**Rule**: AWS-AWSManagedRulesBotControlRuleSet (priority 25)
**Current state**: Version_4.0

**Problem**:
- Bot Control 固定在 Version_4.0
- 之后的版本陆续加入了：
  - 5.0：新增 400 多种 bot，新增 `CategoryPagePreview` 和 `CategoryWebhooks` 两个类别，并调整了匹配顺序，具体的 bot 规则先于通用信号匹配
  - 6.0：Web Bot Authentication 支持区域资源，用这种方式验证过的 bot 在所有类别里都算已验证
  - 6.1：多个类别继续增加特征，包括 Security、SEO 和爬虫框架
- 旧版本能认出的 bot 少得多，各个类别规则能命中的流量也少得多

**Recommendation**:
- 固定到最新的静态版本（见 AWS Managed Rules changelog）。先用 Count 跑一段时间，对比升级前后的标签：5.0 调整了规则的匹配顺序并新增了类别，同一个请求升级后可能命中不同的标签
- 订阅规则组的 SNS 主题，并给固定的版本设置 `DaysToExpiry` 的 CloudWatch 告警

---
## Issue 9 (Medium): 缺少 CRS 和 KnownBadInputs 基线防护规则组

**Rule**: N/A (缺失规则)
**Current state**: Web ACL 中没有 CRS 和 KnownBadInputs

**Problem**:
- CRS 提供 OWASP Top 10 防护（SQLi、XSS 等），是大多数 Web 应用的基础防护层
- KnownBadInputsRuleSet 防护 Log4Shell（CVE-2021-44228）、Java 反序列化漏洞等已知恶意输入模式，WCU 消耗低、误报率低

**Recommendation**:
- 评估是否需要添加 CRS；如果添加，务必将 `SizeRestrictions_Body` 覆盖为 Count，避免对大 payload 的 API 端点产生误报（实现步骤见附录 F）
- 添加 AWSManagedRulesKnownBadInputsRuleSet（WCU 消耗低，建议优先添加）
- 放在 IP 信誉和限速规则之后
- 添加前请在 AWS 控制台确认剩余 WCU 容量（当前已使用 435 WCU，上限 5000）

---
## Issue 10 (Low): ChallengeAllDuringEvent 被覆盖为 Count，DDoS 事件期间的兜底 Challenge 关掉了

**Rule**: AWS-AWSManagedRulesAntiDDoSRuleSet (priority 0)
**Current state**: `ChallengeAllDuringEvent` 被覆盖为 Count

**Problem**:
- `ChallengeAllDuringEvent` 是 AntiDDoS AMR 兜底的软缓解。检测到 DDoS 事件时，它对所有可 Challenge 的请求发起 Challenge，不管是否可疑，用来过滤不能执行 JavaScript 的攻击工具
- 覆盖为 Count 后，事件期间这条规则只产生指标，不做任何缓解
- `DDoSRequests` 会 Block 可疑度为高的请求（`sensitivity_to_block: LOW`）
- `ChallengeDDoSRequests` 仍会 Challenge 可疑度为低、中、高的请求（Challenge 灵敏度 `HIGH`）。少掉的是兜底的 Challenge：事件期间，没有被规则组标为可疑的可 Challenge 请求不再被 Challenge

**Recommendation**:
- **最佳方案**：如果架构支持，使用前后端分离：前端 Web ACL（浏览器流量）启用 ChallengeAllDuringEvent 默认配置；后端 Web ACL（API/原生 App 流量）关闭 Challenge，提高 Block 灵敏度
- **如果前后端共用同一域名**：在同一 Web ACL 中部署双 AMR 实例，一个针对浏览器流量（启用 ChallengeAllDuringEvent），另一个针对 API/原生 App 流量（禁用 Challenge，Block 灵敏度 MEDIUM）。实现步骤见附录 B
- 不推荐"单实例 + 全部 Count + 自定义标签规则"方案：需要理解 6+ 个 AMR 标签的语义，Count 覆盖会禁用 AMR 内置联动逻辑，且仍需回答"哪些路径可以 Challenge"

---
## Issue 11 (Low): 有 11 组规则完全相同

**Rules**: spec_43_JA4_DDoS (priority 1), spec_43_JA4_DDoS_2 (priority 14), challenge-all-reasonable-specific_path_2 (priority 2), challenge-all-reasonable-specific_path (priority 15), chat_platform_deny_options_method_2 (priority 3), chat_platform_deny_options_method (priority 16), probe_service_pass_2 (priority 4), probe_service_pass (priority 17), example-com_ratelimit_challenge_2 (priority 7), example-com_ratelimit_challenge (priority 18), APP-BYPASS_2 (priority 8), APP-BYPASS (priority 19), ban_chat_ipv6_2 (priority 9), ban_chat_ipv6 (priority 20), platform-all-ratelimit_2 (priority 10), platform-all-ratelimit (priority 21), chat-all-ratelimit_2 (priority 11), chat-all-ratelimit (priority 22), chat_challengeable-request_bot_control_2 (priority 12), chat_challengeable-request_bot_control (priority 23), platform_create_payment_bot_control (priority 13), platform_create_payment_bot_control_2 (priority 24)
**Current state**: 这些规则除了名字和 priority，其他配置完全一样

**Problem**:
- 每组里排在前面的规则已经决定了它匹配到的请求怎么处理，后面的副本不会改变任何结果，只是多占 WCU，改规则时还得记得两边一起改
- `spec_43_JA4_DDoS`（priority 1） / `spec_43_JA4_DDoS_2`（priority 14）
- `challenge-all-reasonable-specific_path_2`（priority 2） / `challenge-all-reasonable-specific_path`（priority 15）
- `chat_platform_deny_options_method_2`（priority 3） / `chat_platform_deny_options_method`（priority 16）
- `probe_service_pass_2`（priority 4） / `probe_service_pass`（priority 17）
- `example-com_ratelimit_challenge_2`（priority 7） / `example-com_ratelimit_challenge`（priority 18）
- `APP-BYPASS_2`（priority 8） / `APP-BYPASS`（priority 19）
- `ban_chat_ipv6_2`（priority 9） / `ban_chat_ipv6`（priority 20）
- `platform-all-ratelimit_2`（priority 10） / `platform-all-ratelimit`（priority 21）
- `chat-all-ratelimit_2`（priority 11） / `chat-all-ratelimit`（priority 22）
- `chat_challengeable-request_bot_control_2`（priority 12） / `chat_challengeable-request_bot_control`（priority 23）
- `platform_create_payment_bot_control`（priority 13） / `platform_create_payment_bot_control_2`（priority 24）

**Recommendation**:
- 每组删掉排在后面的那条。前面那条先执行，删掉后 ACL 的行为不变
- 检查有没有 CloudWatch 告警或仪表盘用到被删规则的指标名
- 如果两条本来就想做不同的事，把条件改成真正不一样

---
## Issue 12 (Low): Bot Control 的 CategorySearchEngine 和 CategorySeo 被覆盖为 Allow

**Rule**: AWS-AWSManagedRulesBotControlRuleSet (priority 25)
**Current state**: `CategorySearchEngine / CategorySeo` 被覆盖为 Allow

**Problem**:
- 这两个规则的 Allow 覆盖只影响"未验证"的搜索引擎 Bot（自称是搜索引擎爬虫但无法通过反向 DNS 验证的请求）
- 真正的 Googlebot/Bingbot（已验证）本来就不会被这两个规则 Block，它们带着 `bot:verified` 标签直接放行，与覆盖无关
- 伪造 Googlebot UA 的攻击者不会匹配 `CategorySearchEngine`（反向 DNS 验证失败后落入 `SignalNonBrowserUserAgent`），也与覆盖无关
- Allow 覆盖让未验证的搜索引擎 Bot 绕过所有后续 WAF 规则，虽然 blast radius 有限，但并非必要

**Recommendation**:
- 移除 `CategorySearchEngine / CategorySeo` 的 Allow 覆盖，恢复默认 Block
- 如果担心 DDoS 事件期间爬虫被 Challenge 影响 SEO，正确做法是添加 ASN + UA 爬虫标记规则（见附录 A），而不是在 Bot Control 中使用 Allow 覆盖

---
## Issue 13 (Low): allow_all 规则与默认 Allow 动作重复

**Rule**: allow_all (priority 26)
**Current state**: `uri_path STARTS_WITH '/'` → Allow，而 Web ACL 的 default_action 已经是 Allow

**Problem**:
- 该规则匹配所有请求（任何 URI 都以 `/` 开头），action 为 Allow
- Web ACL 的 default_action 已经是 Allow，因此该规则完全冗余
- 该规则消耗 WCU 且增加规则评估开销，没有任何实际作用

**Recommendation**:
- 删除 allow_all 规则

---
## Issue 14 (Low): 缺少爬虫标记规则，DDoS 事件期间搜索引擎爬虫可能被 Challenge

**Rule**: N/A (缺失规则)
**Current state**: Web ACL 中没有 ASN + UA 爬虫标记规则

**Problem**:
- `ChallengeAllDuringEvent` 会在 DDoS 事件期间对所有可 Challenge 的请求发起 Challenge，包括搜索引擎爬虫（Googlebot、Bingbot 等）
- 真实案例表明，爬虫在 DDoS 事件期间可能索引 Challenge 拦截页（HTTP 202）而非实际内容，严重损害 SEO 排名
- Bot Control 的 `bot:verified` 标签虽然可以识别已验证爬虫，但 Bot Control 必须放在规则链末尾（成本优化），此时 AntiDDoS AMR 已经评估完毕，无法使用该标签
- `ChallengeAllDuringEvent` 现在是 Count，规则组目前不会对爬虫一律 Challenge。重新打开它之前先加上这条规则

**Recommendation**:
- 在 AntiDDoS AMR 之前添加 ASN + UA 爬虫标记规则，为 Google（ASN 15169）、Bing（ASN 8075）等爬虫添加 `crawler:verified` 标签（完整规则 JSON 见附录 A）
- 在 AntiDDoS AMR 的 scope-down 中排除 `crawler:verified` 标签，防止爬虫被 Challenge

---
## Issue 15 (Low): Token Domain 配置包含冗余子域名

**Rule**: N/A (Web ACL 全局配置)
**Current state**: token_domains 包含 `example.com`, `www.example.com`, `chat.example.com`, `platform.example.com`, `api.example.com`, `api-docs.example.com`

**Problem**:
- Token Domain 使用后缀匹配，`example.com` 自动覆盖所有子域名
- 列出子域名是冗余的，不会造成安全问题，但增加了配置维护成本

**Recommendation**:
- 仅保留 `example.com`，删除其他子域名条目

---
## Issue 16 (Awareness): spec_43_JA4_DDoS / spec_43_JA4_DDoS_2 规则为 Count 但未添加标签，仅产生指标

**Rules**: spec_43_JA4_DDoS (priority 1), spec_43_JA4_DDoS_2 (priority 14)
**Current state**: Count action，无 RuleLabels

**Problem**:
- Count 规则不添加标签时，只产生 CloudWatch 指标，下游规则无法基于此匹配结果采取行动
- 如果意图是基于匹配结果执行某种动作，当前配置无法实现

**Recommendation**:
- 如果这些规则只是用来观察，把名字改得能看出用途
- 如果意图是对匹配结果采取行动（如 Block 或 Challenge），应将 action 改为目标动作，或添加标签供下游规则消费

---
## Issue 17 (Awareness): 未检测到 WAF 日志配置

**Rule**: N/A (Web ACL 全局配置)
**Current state**: WAF JSON 导出文件中不包含日志配置信息

**Problem**:
- WAF JSON 导出不包含日志配置。这一条不代表日志未启用，仅表示无法从导出文件中验证
- WAF 日志对于安全事件调查、规则调优和误报分析至关重要

**Recommendation**:
- 通过 AWS 控制台或 CLI 确认是否已启用 WAF 日志（Kinesis Data Firehose、S3 或 CloudWatch Logs）
- 建议至少保留 90 天的日志，并配置 CloudWatch 告警监控关键指标（Block 率、Challenge 率）

---
