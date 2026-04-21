## Issue 1 (Critical): probe_service_pass_2 / probe_service_pass 基于可伪造条件实现全局 Allow 绕过

**Rule**: probe_service_pass_2 (priority 4), probe_service_pass (priority 17)
**Current state**: single_header:x-detect-header EXACTLY 'cloud-detect-16TNBPz9L00rabcdefgh'，action 为 Allow，无 scope-down

**Problem**:
- single_header:x-detect-header 是完全可伪造的，攻击者只需在请求中添加 the matching custom header 即可绕过所有后续规则（包括 IP 信誉、Bot Control、速率限制等）
- 该规则的 blast radius 为全局——所有流量路径均受影响，无 host 或 URI 限制
- 2 条规则逻辑完全相同，只需保留一条
- 匹配值 `cloud-detect-16TNBPz9L00rabcde...` 存储在 WAF 配置中，任何能读取 Web ACL 配置的人均可获取——泄露即意味着完全绕过 WAF

**Recommendation**:
- 将 action 改为 Count+Label（如 `custom:native-app` 或 `custom:probe`），不要直接 Allow——该流量不需要绕过 WAF
- 如果此规则用于内部探针或监控工具，应改用不可伪造的条件（如 IP Set 或 WAF Token）
- 删除重复规则，保留一条即可
- 定期轮换密钥值，并审计 WAF 配置的 IAM 访问权限

---
## Issue 2 (Critical): HostingProviderIPList 被覆盖为 Allow，云端攻击流量可绕过所有后续规则

**Rule**: AWS-AWSManagedRulesAnonymousIpList (priority 6)
**Current state**: `HostingProviderIPList` 规则被覆盖为 Allow

**Problem**:
- `HostingProviderIPList` 默认 Block 云托管和 Web 托管提供商的 IP。将其覆盖为 Allow 意味着来自云平台（AWS、GCP、Azure 等）的所有流量将直接被放行，跳过所有后续规则
- 现代 DDoS 攻击大量使用云托管基础设施（VPS、云函数、容器）——Allow 覆盖使这些攻击流量完全绕过 IP 信誉、Bot Control、速率限制等所有保护
- 正确做法是覆盖为 Count（保留标签，供下游规则使用），而非 Allow

**Recommendation**:
- 将 `HostingProviderIPList` 的覆盖从 Allow 改为 Count
- 如果担心企业用户通过云代理访问时被误封，Count 模式已经解决了这个问题（不会 Block，只添加标签）

---
## Issue 3 (Critical): APP-BYPASS_2 / APP-BYPASS 基于可伪造条件实现全局 Allow 绕过

**Rule**: APP-BYPASS_2 (priority 8), APP-BYPASS (priority 19)
**Current state**: single_header:user-agent STARTS_WITH 'example'，action 为 Allow，无 scope-down

**Problem**:
- single_header:user-agent 是完全可伪造的，攻击者只需在请求中添加 the matching User-Agent header 即可绕过所有后续规则（包括 IP 信誉、Bot Control、速率限制等）
- 该规则的 blast radius 为全局——所有流量路径均受影响，无 host 或 URI 限制
- 2 条规则逻辑完全相同，只需保留一条

**Recommendation**:
- 将 action 改为 Count+Label（如 `custom:native-app` 或 `custom:probe`），不要直接 Allow——该流量不需要绕过 WAF
- 如果此规则用于内部探针或监控工具，应改用不可伪造的条件（如 IP Set 或 WAF Token）
- 删除重复规则，保留一条即可

---
## Issue 4 (Medium): ChallengeAllDuringEvent 被覆盖为 Count，DDoS 事件期间软缓解失效

**Rule**: AWS-AWSManagedRulesAntiDDoSRuleSet (priority 0)
**Current state**: `ChallengeAllDuringEvent` 被覆盖为 Count

**Problem**:
- `ChallengeAllDuringEvent` 是 AntiDDoS AMR 的核心软缓解机制——在检测到 DDoS 事件时，对所有可 Challenge 的请求发起 Challenge，过滤无法执行 JavaScript 的攻击工具
- 将其覆盖为 Count 意味着 DDoS 事件期间该规则只产生指标，不执行任何缓解动作
- 当前配置中 `sensitivity_to_block: LOW`，只有high-suspicion DDoS 请求才会被 Block；`ChallengeAllDuringEvent` 被禁用后，medium and low-suspicion攻击流量在事件期间将不受任何软缓解保护

**Recommendation**:
- **最佳方案**：如果架构支持，使用前后端分离——前端 Web ACL（浏览器流量）启用 ChallengeAllDuringEvent 默认配置；后端 Web ACL（API/原生 App 流量）关闭 Challenge，提高 Block 灵敏度
- **推荐方案**：在同一 Web ACL 中部署双 AMR 实例——一个针对浏览器流量（启用 ChallengeAllDuringEvent），另一个针对 API/原生 App 流量（禁用 Challenge，Block 灵敏度 MEDIUM）。实现步骤见附录 B
- 不推荐"单实例 + 全部 Count + 自定义标签规则"方案——需要理解 6+ 个 AMR 标签的语义，Count 覆盖会禁用 AMR 内置联动逻辑，且仍需回答"哪些路径可以 Challenge"

---
## Issue 5 (Medium): AntiDDoS AMR 的豁免 URI 正则表达式未锚定，攻击者可利用路径注入绕过

**Rule**: AWS-AWSManagedRulesAntiDDoSRuleSet (priority 0)
**Current state**: 豁免正则 `\/query|\/models|\/messages|\/balance|\/completions|\/api\/|\.(acc|avi|css|gif|ico|jpe?g|js|json|mp[34]|ogg|otf|pdf|png|tiff?|ttf|webm|webp|woff2?|xml|svg)$`，API 路径分支未使用 `^` 锚定

**Problem**:
- 以下正则分支未以 `^` 锚定，意味着它们是"包含"匹配而非"以...开头"匹配：`\/query`, `\/models`, `\/messages`, `\/balance`, `\/completions`, `\/api\/`
- 攻击者可以构造包含这些关键词的任意路径来绕过 `ChallengeAllDuringEvent`，例如：`/admin/query/export`, `/admin/models/export`
- 这使得攻击者可以通过精心构造的路径，让攻击请求被豁免于 Challenge

**Recommendation**:
- 为所有 API 路径分支添加 `^` 锚定：`^\/query|^\/models|^\/messages|^\/balance|^\/completions|^\/api\/|^\.(acc|avi|css|gif|ico|jpe?g|js|json|mp[34]|ogg|otf|pdf|png|tiff?|ttf|webm|webp|woff2?|xml|svg)$`
- 静态资源后缀匹配已正确使用 `$` 锚定，无需修改

---
## Issue 6 (Medium): 规则优先级顺序存在问题——发现 3 处顺序问题

**Rule**: 多条规则
**Current state**: AWS-AWSManagedRulesAntiDDoSRuleSet (P0), spec_43_JA4_DDoS (P1), challenge-all-reasonable-specific_path_2 (P2), chat_platform_deny_options_method_2 (P3), probe_service_pass_2 (P4) ... (27 rules total)

**Problem**:
- spec_43_JA4_DDoS (P1, Custom Block/Challenge rules) is before AWS-AWSManagedRulesAmazonIpReputationList (P5, IP reputation / Anonymous IP), but recommended order is reversed
- spec_43_JA4_DDoS (P1, Custom Block/Challenge rules) is before example-com_ratelimit_challenge_2 (P7, Rate-based rules), but recommended order is reversed
- AWS-AWSManagedRulesBotControlRuleSet (P25, Bot Control / ATP / ACFP) is before allow_all (P26, Custom Block/Challenge rules), but recommended order is reversed

**Recommendation**:
- 清理重复规则后，重新整理优先级顺序
- 建议顺序（参考附录 D）：
  1. 爬虫标记规则
  2. AntiDDoS AMR
  3. IP 信誉 + 匿名 IP
  4. 速率限制规则
  5. 自定义 Block/Challenge 规则
  6. Landing Page Always-on Challenge
  7. Bot Control（最后，按请求计费，放最后最省成本）

---
## Issue 7 (Medium): Challenge 规则作用于 API/POST 路径，实际效果等同于 Block

**Rule**: challenge-all-reasonable-specific_path_2 (priority 2), platform_create_payment_bot_control (priority 13), challenge-all-reasonable-specific_path (priority 15), platform_create_payment_bot_control_2 (priority 24)
**Current state**: 对 API 路径和/或 POST 请求应用 Challenge action

**Problem**:
- Challenge 只能由浏览器 GET 请求完成（需要执行 JavaScript 并接受 HTML 响应）
- API 路径通常由原生 App 或 JavaScript fetch/XHR 访问，无法完成 Challenge
- POST 请求无法完成 Challenge——客户端会收到 HTTP 202 但无法重新提交原始 POST 请求
- 实际效果：这些规则对 API 客户端和原生 App 等同于 Block

**Recommendation**:
- 对 API 滥用防护：考虑改用速率限制（rate-based rule）而非 Challenge
- 对 POST 端点：应在对应的 GET 页面（landing page）上应用 Challenge，而不是在 POST 请求上

---
## Issue 8 (Medium): IP 信誉和匿名 IP 规则组的 scope-down 过窄，仅检查首页

**Rule**: AWS-AWSManagedRulesAmazonIpReputationList (priority 5) and AWS-AWSManagedRulesAnonymousIpList (priority 6)
**Current state**: scope-down 为 `uri_path EXACTLY '/'`，仅对首页路径生效

**Problem**:
- 两个规则组实际上只对 `GET /` 请求生效，所有其他路径（`/api/*`、`/login`、`/signup` 等）均不受 IP 信誉检查保护
- 恶意 IP 只需访问任何非首页路径即可完全绕过这两个规则组
- 这使得 IP 信誉保护形同虚设，尤其对 API 路径的攻击毫无防护

**Recommendation**:
- 移除这两个规则组的 scope-down，让其检查所有流量
- 如果出于性能或成本考虑需要限制范围，至少应覆盖所有关键路径，而不是仅限于首页

---
## Issue 9 (Medium): 缺少爬虫标记规则，DDoS 事件期间搜索引擎爬虫可能被 Challenge

**Rule**: N/A（缺失规则）
**Current state**: Web ACL 中没有 ASN + UA 爬虫标记规则

**Problem**:
- `ChallengeAllDuringEvent` 会在 DDoS 事件期间对所有可 Challenge 的请求发起 Challenge，包括搜索引擎爬虫（Googlebot、Bingbot 等）
- 真实案例表明，爬虫在 DDoS 事件期间可能索引 Challenge 拦截页（HTTP 202）而非实际内容，严重损害 SEO 排名
- Bot Control 的 `bot:verified` 标签虽然可以识别已验证爬虫，但 Bot Control 必须放在规则链末尾（成本优化），此时 AntiDDoS AMR 已经评估完毕，无法使用该标签

**Recommendation**:
- 在 AntiDDoS AMR 之前添加 ASN + UA 爬虫标记规则，为 Google（ASN 15169）、Bing（ASN 8075）等爬虫添加 `crawler:verified` 标签（完整规则 JSON 见附录 A）
- 在 AntiDDoS AMR 的 scope-down 中排除 `crawler:verified` 标签，防止爬虫被 Challenge

---
## Issue 10 (Medium): 缺少 CRS and KnownBadInputs 基线防护规则组

**Rule**: N/A（缺失规则）
**Current state**: Web ACL 中没有 CRS and KnownBadInputs

**Problem**:
- CRS 提供 OWASP Top 10 防护（SQLi、XSS 等），是大多数 Web 应用的基础防护层
- KnownBadInputsRuleSet 防护 Log4Shell（CVE-2021-44228）、Java 反序列化漏洞等已知恶意输入模式，WCU 消耗低、误报率低
- 当前 Web ACL 专注于 DDoS 和 Bot 防护，但缺乏应用层攻击防护

**Recommendation**:
- 评估是否需要添加 CRS；如果添加，务必将 `SizeRestrictions_Body` 覆盖为 Count，避免对大 payload 的 API 端点产生误报（实现步骤见附录 F）
- 添加 AWSManagedRulesKnownBadInputsRuleSet（WCU 消耗低，建议优先添加）
- 添加前请在 AWS 控制台确认剩余 WCU 容量（当前已使用 435 WCU，上限 5000）
---
## Issue 11 (Medium): 缺少 Always-on Challenge，DDoS 防护依赖响应式检测的延迟窗口

**Rule**: N/A（缺失规则）
**Current state**: Web ACL 中没有针对 landing page 的 Always-on Challenge 规则

**Problem**:
- 所有响应式防护（AntiDDoS AMR、速率限制规则）在攻击开始到缓解生效之间都存在不可避免的检测延迟窗口
- Always-on Challenge 是主动式防护——对 landing page 路径持续要求浏览器验证，无需等待攻击检测，从第一个请求起即过滤无法执行 JavaScript 的攻击工具
- 缺少 Always-on Challenge 意味着在检测延迟窗口内，大量非浏览器攻击流量可以无阻碍地到达源站

**Recommendation**:
- 添加两条规则实现 Always-on Challenge（实现步骤见附录 C）：
  1. Count+Label 规则：匹配 landing page URI（`/`、`/login`、`/signup` 等），添加标签 `custom:landing-page`
  2. Challenge 规则：匹配 `custom:landing-page` 标签，应用 Challenge action；在条件中排除 `crawler:verified` 标签（需先实现爬虫标记规则）
- 将 Challenge 规则的 token immunity time 设置为至少 4 小时（14400 秒），避免真实用户频繁被 Challenge

---
## Issue 12 (Low): Bot Control 的 CategorySearchEngine 和 CategorySeo 被覆盖为 Allow

**Rule**: AWS-AWSManagedRulesBotControlRuleSet (priority 25)
**Current state**: `CategorySearchEngine / CategorySeo` 被覆盖为 Allow

**Problem**:
- 这两个规则的 Allow 覆盖只影响"未验证"的搜索引擎 Bot（自称是搜索引擎爬虫但无法通过反向 DNS 验证的请求）
- 真正的 Googlebot/Bingbot（已验证）本来就不会被这两个规则 Block——它们通过 `bot:verified` 标签直接放行，与覆盖无关
- 伪造 Googlebot UA 的攻击者不会匹配 `CategorySearchEngine`（反向 DNS 验证失败后落入 `SignalNonBrowserUserAgent`），也与覆盖无关
- Allow 覆盖让未验证的搜索引擎 Bot 绕过所有后续 WAF 规则，虽然 blast radius 有限，但并非必要

**Recommendation**:
- 移除 `CategorySearchEngine / CategorySeo` 的 Allow 覆盖，恢复默认 Block
- 如果担心 DDoS 事件期间爬虫被 Challenge 影响 SEO，正确做法是添加 ASN + UA 爬虫标记规则（见附录 A），而不是在 Bot Control 中使用 Allow 覆盖

---
## Issue 13 (Low): Bot Control 版本过旧（Version_4.0），建议升级至 5.0

**Rule**: AWS-AWSManagedRulesBotControlRuleSet (priority 25)
**Current state**: 使用 Version_4.0

**Problem**:
- BotControlRuleSet Version_5.0 的 Common level 可识别近 700 种 Bot 类型（基于 UA 和 IP），远超早期版本

**Recommendation**:
- 将 BotControlRuleSet 升级至 Version_5.0
- 升级前在测试环境验证，确认无误报增加

---
## Issue 14 (Low): allow_all 规则与默认 Allow 动作重复

**Rule**: allow_all (priority 26)
**Current state**: `uri_path STARTS_WITH '/'` → Allow，而 Web ACL 的 default_action 已经是 Allow

**Problem**:
- 该规则匹配所有请求（任何 URI 都以 `/` 开头），action 为 Allow
- Web ACL 的 default_action 已经是 Allow，因此该规则完全冗余
- 该规则消耗 WCU 且增加规则评估开销，没有任何实际作用

**Recommendation**:
- 删除 allow_all 规则

---
## Issue 15 (Low): Token Domain 配置包含冗余子域名

**Rule**: N/A（Web ACL 全局配置）
**Current state**: token_domains 包含 `example.com`, `www.example.com`, `chat.example.com`, `platform.example.com`, `api.example.com`, `api-docs.example.com`

**Problem**:
- Token Domain 使用后缀匹配——`example.com` 自动覆盖所有子域名
- 列出子域名是冗余的，不会造成安全问题，但增加了配置维护成本

**Recommendation**:
- 仅保留 `example.com`，删除其他子域名条目

---
## Issue 16 (Awareness): spec_43_JA4_DDoS / spec_43_JA4_DDoS_2 规则为 Count 但未添加标签，仅产生指标

**Rule**: spec_43_JA4_DDoS (priority 1), spec_43_JA4_DDoS_2 (priority 14)
**Current state**: Count action，无 RuleLabels

**Problem**:
- Count 规则不添加标签时，只产生 CloudWatch 指标，下游规则无法基于此匹配结果采取行动
- 如果意图是基于匹配结果执行某种动作，当前配置无法实现
- 2 条规则可能逻辑相同——请检查是否存在重复

**Recommendation**:
- 如果这些规则是监控用途（仅观察），保留一条并添加说明性命名即可，删除重复规则
- 如果意图是对匹配结果采取行动（如 Block 或 Challenge），应将 action 改为目标动作，或添加标签供下游规则消费
- 如果逻辑相同，删除重复规则

---
## Issue 17 (Awareness): 速率限制规则存在重复，每对规则逻辑完全相同

**Rule**: example-com_ratelimit_challenge_2 (P7) / example-com_ratelimit_challenge (P18); platform-all-ratelimit_2 (P10) / platform-all-ratelimit (P21); chat-all-ratelimit_2 (P11) / chat-all-ratelimit (P22)
**Current state**: 3 对速率限制规则，scope-down、limit 和 window完全相同

**Problem**:
- 对于 scope-down 重叠的速率限制规则，只有阈值最低的规则会对重叠流量生效——阈值更高的重复规则没有额外效果
- 重复规则消耗 WCU 且增加维护成本

**Recommendation**:
- 删除低优先级的重复规则，保留高优先级版本
- 如果两组规则有不同的业务意图（例如一组用于监控、一组用于执行），应在命名和配置上加以区分

---
## Issue 18 (Awareness): 未检测到 WAF 日志配置

**Rule**: N/A（Web ACL 全局配置）
**Current state**: WAF JSON 导出文件中不包含日志配置信息

**Problem**:
- WAF JSON 导出不包含日志配置——此发现不代表日志未启用，仅表示无法从导出文件中验证
- WAF 日志对于安全事件调查、规则调优和误报分析至关重要

**Recommendation**:
- 通过 AWS 控制台或 CLI 确认是否已启用 WAF 日志（Kinesis Data Firehose、S3 或 CloudWatch Logs）
- 建议至少保留 90 天的日志，并配置 CloudWatch 告警监控关键指标（Block 率、Challenge 率）

---
