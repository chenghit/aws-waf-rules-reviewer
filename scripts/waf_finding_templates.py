"""Finding templates for WAF review reports (English and Chinese)."""

# ── English Templates ──────────────────────────────────────────────────────

TEMPLATES_EN = {
"forgeable_allow": """## Issue {n} (Critical): {rule_names} — forgeable Allow rule bypasses all subsequent protections

**Rule**: {rule_line}
**Current state**: {stmt_summary}, action Allow, no scope-down

**Problem**:
- {forgeable_fields} {is_are} fully forgeable — an attacker can add {forgeable_example} to bypass all subsequent rules (IP reputation, Bot Control, rate limiting, etc.)
- The blast radius is global — all traffic paths are affected, no host or URI restriction
{dup_note}{opaque_note}
**Recommendation**:
- Change action to Count+Label (e.g., `custom:native-app` or `custom:probe`) instead of Allow — the traffic does not need to bypass WAF entirely
- If the rule is for internal probes or monitoring, use an unforgeable condition (IP Set or WAF Token) instead
{dup_rec}{opaque_rec}
---
""",
"hosting_provider_allow": """## Issue {n} (Critical): HostingProviderIPList overridden to Allow — cloud-hosted attack traffic bypasses all subsequent rules

**Rule**: {rule_name} (priority {priority})
**Current state**: `HostingProviderIPList` overridden to Allow

**Problem**:
- `HostingProviderIPList` default-Blocks cloud hosting and web hosting provider IPs. Overriding to Allow means all traffic from cloud platforms (AWS, GCP, Azure, etc.) is immediately allowed, skipping all subsequent rules
- Modern DDoS attacks heavily use cloud infrastructure (VPS, cloud functions, containers) — Allow override lets this attack traffic bypass IP reputation, Bot Control, rate limiting, and all other protections
- The correct approach is to override to Count (preserves labels for downstream rules), not Allow

**Recommendation**:
- Change `HostingProviderIPList` override from Allow to Count
- Count mode does not Block — it only adds labels, so enterprise users routed through cloud proxies are not affected

---
""",
"scope_down_too_narrow": """## Issue {n} (Medium): IP reputation / Anonymous IP rule groups have overly narrow scope-down — only inspects homepage

**Rule**: {rule_line}
**Current state**: scope-down is `uri_path EXACTLY '/'`, only applies to homepage path

**Problem**:
- Both rule groups only inspect `GET /` requests — all other paths (`/api/*`, `/login`, `/signup`, etc.) are not covered by IP reputation checks
- Malicious IPs only need to target any non-homepage path to completely bypass both rule groups
- This renders IP reputation protection effectively useless, especially for API path attacks

**Recommendation**:
- Remove the scope-down from both rule groups to inspect all traffic
- If scope restriction is needed for performance or cost, at minimum cover all critical paths, not just the homepage

---
""",
"challenge_on_post_api": """## Issue {n} (Medium): Challenge rules target API/POST paths — effectively equivalent to Block

**Rule**: {rule_line}
**Current state**: Challenge action applied to API paths and/or POST requests

**Problem**:
- Challenge can only be completed by browser GET requests (requires JavaScript execution and HTML response)
- API paths are typically accessed by native apps or JavaScript fetch/XHR, which cannot complete Challenge
- POST requests cannot complete Challenge — the client receives HTTP 202 but cannot resubmit the original POST
- Effective result: these rules act as Block for API clients and native apps

**Recommendation**:
- For API abuse prevention: consider rate-based rules instead of Challenge
- For POST endpoints: apply Challenge on the GET landing page before the POST, so users acquire a WAF token first
{dup_rec}
---
""",
"missing_baseline": """## Issue {n} ({severity}): Missing {missing_names} baseline protection rule groups

**Rule**: N/A (missing rule)
**Current state**: Web ACL does not contain {missing_names}

**Problem**:
- {missing_detail}

**Recommendation**:
{missing_rec}
---
""",
"token_domain": """## Issue {n} (Low): Token Domain configuration contains redundant subdomains

**Rule**: N/A (Web ACL global configuration)
**Current state**: token_domains contains {domain_list}

**Problem**:
- Token Domain uses suffix matching — `{apex}` automatically covers all subdomains at any depth
- Listing subdomains is redundant; it does not cause security issues but adds configuration maintenance cost

**Recommendation**:
- Keep only `{apex}`, remove all subdomain entries

---
""",
"no_logging": """## Issue {n} (Awareness): No WAF logging configuration detected

**Rule**: N/A (Web ACL global configuration)
**Current state**: WAF JSON export does not include logging configuration

**Problem**:
- WAF logging configuration is not included in the Web ACL JSON export — this finding does not mean logging is disabled, only that it cannot be verified from the export
- WAF logs are essential for security incident investigation, rule tuning, and false positive analysis

**Recommendation**:
- Verify that WAF logging is enabled (Kinesis Data Firehose, S3, or CloudWatch Logs) via the AWS Console or CLI
- Recommend retaining at least 90 days of logs and configuring CloudWatch alarms for key metrics (Block rate, Challenge rate)

---
""",
"logging_disabled": """## Issue {n} (Awareness): WAF logging is not enabled

**Rule**: N/A (Web ACL global configuration)
**Current state**: `get-logging-configuration` returned no logging configuration for this Web ACL

**Problem**:
- No request logs are recorded, so blocked or challenged requests cannot be traced after the fact
- Without logs, false positives, rule tuning, and incident investigation have to rely on sampled requests and CloudWatch metrics only

**Recommendation**:
- Enable WAF logging to CloudWatch Logs, S3, or Kinesis Data Firehose
- Recommend retaining at least 90 days of logs and configuring CloudWatch alarms for key metrics (Block rate, Challenge rate)

---
""",
"default_action_redundancy": """## Issue {n} (Low): {rule_name} rule is redundant with default Allow action

**Rule**: {rule_name} (priority {priority})
**Current state**: `{stmt_summary}` → Allow, while Web ACL default_action is already Allow

**Problem**:
- This rule matches all requests (any URI starts with `/`), action is Allow
- The Web ACL default_action is already Allow, making this rule completely redundant
- The rule consumes WCU and adds evaluation overhead with no practical effect

**Recommendation**:
- Remove the {rule_name} rule

---
""",
"count_without_labels": """## Issue {n} (Awareness): {rule_names} — Count rules without labels, metric-only

**Rule**: {rule_line}
**Current state**: Count action, no RuleLabels

**Problem**:
- Count rules without labels only produce CloudWatch metrics — downstream rules cannot act on the match result
- If the intent is to take action based on these matches, the current configuration cannot achieve it
{dup_note}
**Recommendation**:
- If these rules are for monitoring only, keep one and add descriptive naming; remove duplicates
- If the intent is to act on matches (Block, Challenge, etc.), either change the action or add labels for downstream rules to consume
{dup_rec}
---
""",
"challenge_all_during_event": """## Issue {n} (Medium): ChallengeAllDuringEvent overridden to Count — soft mitigation disabled during DDoS events

**Rule**: {rule_name} (priority {priority})
**Current state**: `ChallengeAllDuringEvent` overridden to Count

**Problem**:
- `ChallengeAllDuringEvent` is AntiDDoS AMR's core soft mitigation — during DDoS events, it Challenges all challengeable requests, filtering attack tools that cannot execute JavaScript
- Overriding to Count means this rule only produces metrics during DDoS events, with no mitigation action
- With `sensitivity_to_block: {block_sens}`, only {block_desc} DDoS requests are Blocked; disabling ChallengeAllDuringEvent leaves {remaining_desc} attack traffic with no soft mitigation

**Recommendation**:
- **Best**: if architecture supports it, use separate Web ACLs for frontend (browser) and backend (API/native app) traffic. Frontend Web ACL enables ChallengeAllDuringEvent with default config; backend Web ACL disables Challenge and raises Block sensitivity
- **If frontend and API share the same domain**: deploy dual AMR instances in the same Web ACL — one for browser traffic (ChallengeAllDuringEvent enabled), one for API/native app traffic (Challenge disabled, Block sensitivity MEDIUM). See Appendix B for implementation steps
- Do NOT use the "single instance + all Count + custom label rules" pattern — it requires understanding 6+ AMR labels, disables AMR's internal coordination logic, and still requires answering which paths can Challenge

---
""",
"unanchored_exempt_regex": """## Issue {n} (Medium): AntiDDoS AMR exempt URI regex is unanchored — attackers can bypass via path injection

**Rule**: {rule_name} (priority {priority})
**Current state**: Exempt regex `{regex}`, API path branches are not anchored with `^`

**Problem**:
- The following regex branches are not anchored with `^`, meaning they are "contains" matches rather than "starts-with": {unanchored_list}
- Attackers can craft paths containing these keywords to bypass `ChallengeAllDuringEvent`, e.g.: {examples}
- This allows attack requests to be exempted from Challenge during DDoS events

**Recommendation**:
- Add `^` anchoring to all API path branches: {anchored_suggestion}
- Static asset suffix matching (e.g., `\\.(css|js|png)$`) is already correctly anchored with `$` — no change needed

---
""",
"missing_crawler_labeling": """## Issue {n} (Medium): Missing crawler labeling rule — search engine crawlers may be Challenged during DDoS events

**Rule**: N/A (missing rule)
**Current state**: No ASN + UA crawler labeling rule in the Web ACL

**Problem**:
- `ChallengeAllDuringEvent` will Challenge all challengeable requests during DDoS events, including search engine crawlers (Googlebot, Bingbot, etc.)
- Real-world cases show crawlers may index the Challenge interstitial page (HTTP 202) instead of actual content during DDoS events, severely damaging SEO rankings
- Bot Control's `bot:verified` label can identify verified crawlers, but Bot Control must be placed last in the rule chain (cost optimization) — by then AntiDDoS AMR has already evaluated the request

**Recommendation**:
- Add an ASN + UA crawler labeling rule before AntiDDoS AMR to label Google (ASN 15169), Bing (ASN 8075), and other crawlers with `crawler:verified` (full rule JSON in Appendix A)
- Add a scope-down to AntiDDoS AMR excluding the `crawler:verified` label

---
""",
"bot_control_search_allow": """## Issue {n} (Low): Bot Control CategorySearchEngine/CategorySeo overridden to Allow

**Rule**: {rule_name} (priority {priority})
**Current state**: `{override_names}` overridden to Allow

**Problem**:
- These Allow overrides only affect "unverified" search engine bots — requests claiming to be search engine crawlers but failing reverse DNS verification
- Real Googlebot/Bingbot (verified) are already not Blocked by these rules — they pass through with `bot:verified` label regardless of the override
- Forged Googlebot UAs (reverse DNS fails) do NOT match `CategorySearchEngine` — they fall through to `SignalNonBrowserUserAgent` and are Blocked, regardless of the override
- The Allow override lets unverified search engine bots bypass all subsequent WAF rules — limited blast radius, but unnecessary

**Recommendation**:
- Remove the Allow overrides on `{override_names}`, restore default Block
- For SEO protection during DDoS events, use the ASN + UA crawler labeling rule (see Appendix A) instead of Bot Control Allow overrides

---
""",
"duplicate_rules": """## Issue {n} (Awareness): Duplicate {rule_type} rules — each pair has identical logic

**Rule**: {rule_line}
**Current state**: {pair_count} pairs of {rule_type} rules with identical {match_desc}

**Problem**:
- {dup_problem}
- Duplicate rules consume WCU and increase maintenance cost

**Recommendation**:
- Remove the lower-priority duplicate from each pair, keeping the higher-priority version
- If the pairs have different business intent (e.g., one for monitoring, one for enforcement), differentiate them in naming and configuration

---
""",
"missing_always_on_challenge": """## Issue {n} (Medium): Missing Always-on Challenge — DDoS protection relies on reactive detection delay

**Rule**: N/A (missing rule)
**Current state**: No Always-on Challenge rules for landing pages in the Web ACL

**Problem**:
- All reactive protections (AntiDDoS AMR, rate-based rules) have an inherent delay between attack start and mitigation activation
- Always-on Challenge is proactive — it continuously requires browser verification on landing page paths, filtering non-browser attack traffic from the first request with zero detection delay
- Without Always-on Challenge, non-browser DDoS traffic can reach the origin unimpeded during the detection delay window

**Recommendation**:
- Add two rules to implement Always-on Challenge (see Appendix C):
  1. Count+Label rule: match landing page URIs (`/`, `/login`, `/signup`, etc.), add label `custom:landing-page`
  2. Challenge rule: match `custom:landing-page` label, apply Challenge action; exclude `crawler:verified` label (requires crawler labeling rule from Appendix A)
- Set Challenge rule token immunity time to at least 4 hours (14400 seconds) to minimize impact on real users

---
""",
"opaque_search_string": """## Issue {n} (Awareness): {rule_name} contains opaque/hash-like search_string value

**Rule**: {rule_name} (priority {priority})
**Current state**: {stmt_summary}

**Problem**:
- The match value `{value}` appears to be a shared secret, hash, or token
- {risk_note}
- Anyone with read access to the Web ACL configuration (including IAM users with overly broad permissions) can obtain this value

**Recommendation**:
- {rec_note}
- Periodically rotate the value and audit IAM access to WAF configuration

---
""",
"managed_allow_override": """## Issue {n} (Awareness): Managed rule group has Allow override — bypasses all subsequent rules

**Rule**: {rule_name} (priority {priority})
**Current state**: {override_detail}

**Problem**:
- Overriding a managed rule to Allow means matching requests are immediately allowed and skip ALL remaining rules — both within the rule group and in the Web ACL
- This is the most dangerous override type; it creates a potential bypass path

**Recommendation**:
- Review whether Allow is truly needed; in most cases, Count (preserves labels, request continues) is the safer choice
- If Allow is intentional, document the business justification

---
""",
"order_issues": """## Issue {n} ({severity}): Rule order issues: {summary}

**Rules**: {rule_line}
**Current state**: Existing rules are evaluated in an order that changes what gets inspected or blocked

**Problem**:
{problems}

**Recommendation**:
{recs}
- When adding new rule types, see Appendix D for where they belong

---
""",
"recommended_protections": """## Issue {n} ({severity}): Recommended protections not deployed: {names}

**Rule**: N/A (missing rule)
**Current state**: This Web ACL allows traffic by default and serves internet traffic without these protections

**Problem**:
{problems}

**Recommendation**:
{recs}
- Add each one in Count first, review what it matches, then switch to its default actions

---
""",
"bot_control_version": """## Issue {n} (Medium): Bot Control runs an old version with much weaker detection

**Rule**: {rule_name} (priority {priority})
**Current state**: {current_version}

**Problem**:
- {detail}
- Versions 2.0/3.0 added most TARGETED rules (`TGT_TokenAbsent`, the `TGT_TokenReuse*` rules by IP, ASN, and country, `TGT_VolumetricSessionMaximum`, `TGT_SignalBrowserAutomationExtension`). Version 5.0 added 400+ bot signatures and new categories at COMMON level. Later versions keep adding signatures
- On the old version, far fewer bots are recognized, so COMMON-level categories match much less traffic

**Recommendation**:
- Pin the latest static version (see the AWS Managed Rules changelog). Run it in Count first and compare labels with current traffic: 5.0 changed rule match precedence and added categories, so the same request can get different labels after the upgrade
- Subscribe to the rule group's SNS topic and add a CloudWatch alarm on `DaysToExpiry` for the pinned version

---
""",
"managed_unpinned": """## Issue {n} (Low): Managed rule groups not pinned to a version

**Rules**: {rule_line}
**Current state**: No `VersionToUse` on {groups}

**Problem**:
- These rule groups follow the AWS default version. AWS announces default-version changes only through each rule group's SNS topic, not in the changelog, so detection can change without any change to this Web ACL
{sqli_note}
**Recommendation**:
- Pin each rule group to a static version. Test a new version in Count before switching
- Subscribe to each rule group's SNS topic and alarm on `DaysToExpiry` for pinned versions

---
""",
"uri_fragment_fallback": """## Issue {n} ({severity}): UriFragment condition always matches, so the path restriction is void

**Rules**: {rule_line}
**Current state**: {rule_names} match `UriFragment` with `FallbackBehavior: MATCH`

**Problem**:
- `UriFragment` is the part of a URL after `#`. Browsers and HTTP clients don't send it to the server, so the condition falls back to MATCH on every request
{allow_note}

**Recommendation**:
- Match `UriPath` instead. Confirm the sender's real path before changing, then verify its requests still pass

---
""",
"uri_path_pitfalls": """## Issue {n} (Medium): URI path conditions that can never match as written

**Rules**: {rule_line}
**Current state**: Conditions on `UriPath` whose pattern can't match a real path

**Problem**:
{details}

**Recommendation**:
{recs}
- Keep the rule in Count after fixing it, check what it matches, then switch to its intended action

---
""",
"path_block_decoding": """## Issue {n} (Medium): Path Block rules don't URL-decode, so encoded paths slip through

**Rules**: {rule_line}
**Current state**: Block rules match `UriPath` without `URL_DECODE`

**Problem**:
- WAF inspects the raw URI path as the client sent it. Without a decoding transformation, `/%69nternal/` doesn't match `/internal/`. If the origin decodes the path, the request reaches the path the rule meant to block
- `URL_DECODE` decodes once, so double encoding such as `%2569` needs it twice
{details}

**Recommendation**:
- Use this transformation chain on path Block rules, in order: `URL_DECODE`, `URL_DECODE`, `REMOVE_NULLS`, `NORMALIZE_PATH`, `LOWERCASE`
- Test whether the origin decodes paths. If it doesn't, the practical risk is lower

---
""",
"path_only_allow": """## Issue {n} ({severity}): Allow rules match only on request content, with no IP or other unforgeable condition

**Rules**: {rule_line}
**Current state**: {rule_names} allow requests by path (and other request content) alone

**Problem**:
- Anyone who knows or guesses the path gets the request straight to the origin. Allow ends evaluation, so no later rule inspects it
{acl_note}
**Recommendation**:
- Add the sender's IP set where the sender publishes egress IPs
- Otherwise the application must verify request signatures, and content inspection (CRS, KnownBadInputs) scoped to these paths should run before the Allow rules
- Use `EXACTLY`, or a `STARTS_WITH` value as specific as possible

---
""",
"managed_count": """## Issue {n} (Medium): Managed protections left in Count

**Rules**: {rule_line}
**Current state**: Managed rule groups, or rules inside them, set to Count

**Problem**:
{details}
- Count only records metrics and labels, it doesn't block. `SizeRestrictions_BODY` in Count is a common deliberate choice and isn't listed here

**Recommendation**:
- Review Count-period matches rule by rule, then switch rules to their default action
- For rules with confirmed false positives on specific paths, keep them in Count and add a custom rule after the group that blocks their label everywhere except those paths

---
""",
"bot_control_tgt_common": """## Issue {n} (Low): TGT_* overrides have no effect at COMMON inspection level

**Rule**: {rule_name} (priority {priority})
**Current state**: `InspectionLevel: COMMON` with {count} TGT_* overrides: {tgt_list}

**Problem**:
- TGT_* rules only run at TARGETED level, so these overrides do nothing

**Recommendation**:
- Remove them, or move to TARGETED deliberately. TARGETED relies on tokens from Challenge or the JS/mobile SDK and doesn't suit machine-to-machine APIs

---
""",
}

# ── Chinese Templates ──────────────────────────────────────────────────────

TEMPLATES_ZH = {
"forgeable_allow": """## Issue {n} (Critical): {rule_names} 基于可伪造条件实现全局 Allow 绕过

**Rule**: {rule_line}
**Current state**: {stmt_summary}，action 为 Allow，无 scope-down

**Problem**:
- {forgeable_fields} 是完全可伪造的，攻击者只需在请求中添加 {forgeable_example} 即可绕过所有后续规则（包括 IP 信誉、Bot Control、速率限制等）
- 该规则的 blast radius 为全局——所有流量路径均受影响，无 host 或 URI 限制
{dup_note}{opaque_note}
**Recommendation**:
- 将 action 改为 Count+Label（如 `custom:native-app` 或 `custom:probe`），不要直接 Allow——该流量不需要绕过 WAF
- 如果此规则用于内部探针或监控工具，应改用不可伪造的条件（如 IP Set 或 WAF Token）
{dup_rec}{opaque_rec}
---
""",
"hosting_provider_allow": """## Issue {n} (Critical): HostingProviderIPList 被覆盖为 Allow，云端攻击流量可绕过所有后续规则

**Rule**: {rule_name} (priority {priority})
**Current state**: `HostingProviderIPList` 规则被覆盖为 Allow

**Problem**:
- `HostingProviderIPList` 默认 Block 云托管和 Web 托管提供商的 IP。将其覆盖为 Allow 意味着来自云平台（AWS、GCP、Azure 等）的所有流量将直接被放行，跳过所有后续规则
- 现代 DDoS 攻击大量使用云托管基础设施（VPS、云函数、容器）——Allow 覆盖使这些攻击流量完全绕过 IP 信誉、Bot Control、速率限制等所有保护
- 正确做法是覆盖为 Count（保留标签，供下游规则使用），而非 Allow

**Recommendation**:
- 将 `HostingProviderIPList` 的覆盖从 Allow 改为 Count
- 如果担心企业用户通过云代理访问时被误封，Count 模式已经解决了这个问题（不会 Block，只添加标签）

---
""",
"scope_down_too_narrow": """## Issue {n} (Medium): IP 信誉和匿名 IP 规则组的 scope-down 过窄，仅检查首页

**Rule**: {rule_line}
**Current state**: scope-down 为 `uri_path EXACTLY '/'`，仅对首页路径生效

**Problem**:
- 两个规则组实际上只对 `GET /` 请求生效，所有其他路径（`/api/*`、`/login`、`/signup` 等）均不受 IP 信誉检查保护
- 恶意 IP 只需访问任何非首页路径即可完全绕过这两个规则组
- 这使得 IP 信誉保护形同虚设，尤其对 API 路径的攻击毫无防护

**Recommendation**:
- 移除这两个规则组的 scope-down，让其检查所有流量
- 如果出于性能或成本考虑需要限制范围，至少应覆盖所有关键路径，而不是仅限于首页

---
""",
"challenge_on_post_api": """## Issue {n} (Medium): Challenge 规则作用于 API/POST 路径，实际效果等同于 Block

**Rule**: {rule_line}
**Current state**: 对 API 路径和/或 POST 请求应用 Challenge action

**Problem**:
- Challenge 只能由浏览器 GET 请求完成（需要执行 JavaScript 并接受 HTML 响应）
- API 路径通常由原生 App 或 JavaScript fetch/XHR 访问，无法完成 Challenge
- POST 请求无法完成 Challenge——客户端会收到 HTTP 202 但无法重新提交原始 POST 请求
- 实际效果：这些规则对 API 客户端和原生 App 等同于 Block

**Recommendation**:
- 对 API 滥用防护：考虑改用速率限制（rate-based rule）而非 Challenge
- 对 POST 端点：应在对应的 GET 页面（landing page）上应用 Challenge，而不是在 POST 请求上
{dup_rec}
---
""",
"missing_baseline": """## Issue {n} ({severity}): 缺少 {missing_names} 基线防护规则组

**Rule**: N/A（缺失规则）
**Current state**: Web ACL 中没有 {missing_names}

**Problem**:
- {missing_detail}

**Recommendation**:
{missing_rec}
---
""",
"token_domain": """## Issue {n} (Low): Token Domain 配置包含冗余子域名

**Rule**: N/A（Web ACL 全局配置）
**Current state**: token_domains 包含 {domain_list}

**Problem**:
- Token Domain 使用后缀匹配——`{apex}` 自动覆盖所有子域名
- 列出子域名是冗余的，不会造成安全问题，但增加了配置维护成本

**Recommendation**:
- 仅保留 `{apex}`，删除其他子域名条目

---
""",
"no_logging": """## Issue {n} (Awareness): 未检测到 WAF 日志配置

**Rule**: N/A（Web ACL 全局配置）
**Current state**: WAF JSON 导出文件中不包含日志配置信息

**Problem**:
- WAF JSON 导出不包含日志配置——此发现不代表日志未启用，仅表示无法从导出文件中验证
- WAF 日志对于安全事件调查、规则调优和误报分析至关重要

**Recommendation**:
- 通过 AWS 控制台或 CLI 确认是否已启用 WAF 日志（Kinesis Data Firehose、S3 或 CloudWatch Logs）
- 建议至少保留 90 天的日志，并配置 CloudWatch 告警监控关键指标（Block 率、Challenge 率）

---
""",
"logging_disabled": """## Issue {n} (Awareness): 未启用 WAF 日志

**Rule**: N/A（Web ACL 全局配置）
**Current state**: `get-logging-configuration` 显示该 Web ACL 没有日志配置

**Problem**:
- 没有请求日志，被 Block 或 Challenge 的请求事后无法追查
- 排查误报、调规则、调查安全事件时，只能依赖采样请求和 CloudWatch 指标

**Recommendation**:
- 启用 WAF 日志，目标可选 CloudWatch Logs、S3 或 Kinesis Data Firehose
- 建议至少保留 90 天的日志，并配置 CloudWatch 告警监控关键指标（Block 率、Challenge 率）

---
""",
"default_action_redundancy": """## Issue {n} (Low): {rule_name} 规则与默认 Allow 动作重复

**Rule**: {rule_name} (priority {priority})
**Current state**: `{stmt_summary}` → Allow，而 Web ACL 的 default_action 已经是 Allow

**Problem**:
- 该规则匹配所有请求（任何 URI 都以 `/` 开头），action 为 Allow
- Web ACL 的 default_action 已经是 Allow，因此该规则完全冗余
- 该规则消耗 WCU 且增加规则评估开销，没有任何实际作用

**Recommendation**:
- 删除 {rule_name} 规则

---
""",
"count_without_labels": """## Issue {n} (Awareness): {rule_names} 规则为 Count 但未添加标签，仅产生指标

**Rule**: {rule_line}
**Current state**: Count action，无 RuleLabels

**Problem**:
- Count 规则不添加标签时，只产生 CloudWatch 指标，下游规则无法基于此匹配结果采取行动
- 如果意图是基于匹配结果执行某种动作，当前配置无法实现
{dup_note}
**Recommendation**:
- 如果这些规则是监控用途（仅观察），保留一条并添加说明性命名即可，删除重复规则
- 如果意图是对匹配结果采取行动（如 Block 或 Challenge），应将 action 改为目标动作，或添加标签供下游规则消费
{dup_rec}
---
""",
"challenge_all_during_event": """## Issue {n} (Medium): ChallengeAllDuringEvent 被覆盖为 Count，DDoS 事件期间软缓解失效

**Rule**: {rule_name} (priority {priority})
**Current state**: `ChallengeAllDuringEvent` 被覆盖为 Count

**Problem**:
- `ChallengeAllDuringEvent` 是 AntiDDoS AMR 的核心软缓解机制——在检测到 DDoS 事件时，对所有可 Challenge 的请求发起 Challenge，过滤无法执行 JavaScript 的攻击工具
- 将其覆盖为 Count 意味着 DDoS 事件期间该规则只产生指标，不执行任何缓解动作
- 当前配置中 `sensitivity_to_block: {block_sens}`，只有{block_desc} DDoS 请求才会被 Block；`ChallengeAllDuringEvent` 被禁用后，{remaining_desc}攻击流量在事件期间将不受任何软缓解保护

**Recommendation**:
- **最佳方案**：如果架构支持，使用前后端分离——前端 Web ACL（浏览器流量）启用 ChallengeAllDuringEvent 默认配置；后端 Web ACL（API/原生 App 流量）关闭 Challenge，提高 Block 灵敏度
- **如果前后端共用同一域名**：在同一 Web ACL 中部署双 AMR 实例——一个针对浏览器流量（启用 ChallengeAllDuringEvent），另一个针对 API/原生 App 流量（禁用 Challenge，Block 灵敏度 MEDIUM）。实现步骤见附录 B
- 不推荐"单实例 + 全部 Count + 自定义标签规则"方案——需要理解 6+ 个 AMR 标签的语义，Count 覆盖会禁用 AMR 内置联动逻辑，且仍需回答"哪些路径可以 Challenge"

---
""",
"unanchored_exempt_regex": """## Issue {n} (Medium): AntiDDoS AMR 的豁免 URI 正则表达式未锚定，攻击者可利用路径注入绕过

**Rule**: {rule_name} (priority {priority})
**Current state**: 豁免正则 `{regex}`，API 路径分支未使用 `^` 锚定

**Problem**:
- 以下正则分支未以 `^` 锚定，意味着它们是"包含"匹配而非"以...开头"匹配：{unanchored_list}
- 攻击者可以构造包含这些关键词的任意路径来绕过 `ChallengeAllDuringEvent`，例如：{examples}
- 这使得攻击者可以通过精心构造的路径，让攻击请求被豁免于 Challenge

**Recommendation**:
- 为所有 API 路径分支添加 `^` 锚定：{anchored_suggestion}
- 静态资源后缀匹配已正确使用 `$` 锚定，无需修改

---
""",
"missing_crawler_labeling": """## Issue {n} (Medium): 缺少爬虫标记规则，DDoS 事件期间搜索引擎爬虫可能被 Challenge

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
""",
"bot_control_search_allow": """## Issue {n} (Low): Bot Control 的 CategorySearchEngine 和 CategorySeo 被覆盖为 Allow

**Rule**: {rule_name} (priority {priority})
**Current state**: `{override_names}` 被覆盖为 Allow

**Problem**:
- 这两个规则的 Allow 覆盖只影响"未验证"的搜索引擎 Bot（自称是搜索引擎爬虫但无法通过反向 DNS 验证的请求）
- 真正的 Googlebot/Bingbot（已验证）本来就不会被这两个规则 Block——它们通过 `bot:verified` 标签直接放行，与覆盖无关
- 伪造 Googlebot UA 的攻击者不会匹配 `CategorySearchEngine`（反向 DNS 验证失败后落入 `SignalNonBrowserUserAgent`），也与覆盖无关
- Allow 覆盖让未验证的搜索引擎 Bot 绕过所有后续 WAF 规则，虽然 blast radius 有限，但并非必要

**Recommendation**:
- 移除 `{override_names}` 的 Allow 覆盖，恢复默认 Block
- 如果担心 DDoS 事件期间爬虫被 Challenge 影响 SEO，正确做法是添加 ASN + UA 爬虫标记规则（见附录 A），而不是在 Bot Control 中使用 Allow 覆盖

---
""",
"duplicate_rules": """## Issue {n} (Awareness): {rule_type}规则存在重复，每对规则逻辑完全相同

**Rule**: {rule_line}
**Current state**: {pair_count} 对{rule_type}规则，{match_desc}完全相同

**Problem**:
- {dup_problem}
- 重复规则消耗 WCU 且增加维护成本

**Recommendation**:
- 删除低优先级的重复规则，保留高优先级版本
- 如果两组规则有不同的业务意图（例如一组用于监控、一组用于执行），应在命名和配置上加以区分

---
""",
"missing_always_on_challenge": """## Issue {n} (Medium): 缺少 Always-on Challenge，DDoS 防护依赖响应式检测的延迟窗口

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
""",
"opaque_search_string": """## Issue {n} (Awareness): {rule_name} 包含不透明/哈希值的 search_string

**Rule**: {rule_name} (priority {priority})
**Current state**: {stmt_summary}

**Problem**:
- 匹配值 `{value}` 看起来是共享密钥、哈希或 token
- {risk_note}
- 任何能读取 Web ACL 配置的人（包括 IAM 权限过宽的内部人员）均可获取此值

**Recommendation**:
- {rec_note}
- 定期轮换密钥值，并审计 WAF 配置的 IAM 访问权限

---
""",
"managed_allow_override": """## Issue {n} (Awareness): 托管规则组存在 Allow 覆盖——匹配请求将绕过所有后续规则

**Rule**: {rule_name} (priority {priority})
**Current state**: {override_detail}

**Problem**:
- 将托管规则覆盖为 Allow 意味着匹配的请求将被立即放行，跳过所有后续规则——包括同一规则组内和 Web ACL 中的所有规则
- 这是最危险的覆盖类型，会创建潜在的绕过路径

**Recommendation**:
- 评估是否真正需要 Allow；大多数情况下，Count（保留标签，请求继续评估）是更安全的选择
- 如果 Allow 是有意为之，请记录业务理由

---
""",
"order_issues": """## Issue {n} ({severity}): 规则顺序问题，{summary}

**Rules**: {rule_line}
**Current state**: 现有规则的评估顺序，影响到了哪些请求会被检查或拦截

**Problem**:
{problems}

**Recommendation**:
{recs}
- 新增规则类型时放在哪个位置，参考附录 D

---
""",
"recommended_protections": """## Issue {n} ({severity}): 建议补充的防护：{names}

**Rule**: N/A（缺失规则）
**Current state**: 这个 ACL 默认放行，面向公网流量，但没有部署这些防护

**Problem**:
{problems}

**Recommendation**:
{recs}
- 每一项都先用 Count 加进去，看清楚命中的是什么流量，再切回默认动作

---
""",
"bot_control_version": """## Issue {n} (Medium): Bot Control 跑的是旧版本，识别能力弱很多

**Rule**: {rule_name} (priority {priority})
**Current state**: {current_version}

**Problem**:
- {detail}
- 2.0/3.0 版本加入了大部分 TARGETED 规则（`TGT_TokenAbsent`、按 IP、ASN、国家区分的 `TGT_TokenReuse*`、`TGT_VolumetricSessionMaximum`、`TGT_SignalBrowserAutomationExtension`）。5.0 版本在 COMMON 级别新增了 400 多种 bot 特征和新的类别。之后的版本还在继续增加特征
- 旧版本能认出的 bot 少得多，COMMON 级别各个类别能命中的流量也少得多

**Recommendation**:
- 固定到最新的静态版本（见 AWS Managed Rules changelog）。先用 Count 跑一段时间，对比升级前后的标签：5.0 调整了规则的匹配顺序并新增了类别，同一个请求升级后可能命中不同的标签
- 订阅规则组的 SNS 主题，并给固定的版本设置 `DaysToExpiry` 的 CloudWatch 告警

---
""",
"managed_unpinned": """## Issue {n} (Low): 托管规则组没有固定版本

**Rules**: {rule_line}
**Current state**: {groups} 没有设置 `VersionToUse`

**Problem**:
- 这些规则组跟着 AWS 的默认版本走。AWS 调整默认版本时不写进 changelog，只通过各规则组的 SNS 主题通知，所以 ACL 配置没变，检测行为也可能变了
{sqli_note}
**Recommendation**:
- 给每个规则组固定一个静态版本。切换新版本前先用 Count 观察
- 订阅各规则组的 SNS 主题，给固定的版本设置 `DaysToExpiry` 告警

---
""",
"uri_fragment_fallback": """## Issue {n} ({severity}): UriFragment 条件恒为真，路径限制失效

**Rules**: {rule_line}
**Current state**: {rule_names} 用 `UriFragment` 做匹配，且 `FallbackBehavior: MATCH`

**Problem**:
- `UriFragment` 是 URL 里 `#` 后面的部分。浏览器和 HTTP 客户端都不会把它发给服务器，所以每个请求都会走 fallback，被当成匹配
{allow_note}

**Recommendation**:
- 改成匹配 `UriPath`。修改前先确认发送方的真实路径，改完后确认它的请求仍能正常通过

---
""",
"uri_path_pitfalls": """## Issue {n} (Medium): 有些 URI 路径条件按现在的写法永远不会命中

**Rules**: {rule_line}
**Current state**: `UriPath` 上的匹配模式和真实路径对不上

**Problem**:
{details}

**Recommendation**:
{recs}
- 修正后先保持 Count，看清楚命中情况，再切到原本想要的动作

---
""",
"path_block_decoding": """## Issue {n} (Medium): 路径拦截规则没做 URL 解码，编码后的路径可以绕过

**Rules**: {rule_line}
**Current state**: Block 规则匹配 `UriPath` 时没有 `URL_DECODE`

**Problem**:
- WAF 检查的是客户端发来的原始路径。没有解码转换时，`/%69nternal/` 匹配不上 `/internal/`。如果源站会解码，请求就会到达规则本来要拦的路径
- `URL_DECODE` 只解码一次，`%2569` 这种双重编码要写两次
{details}

**Recommendation**:
- 路径拦截规则按这个顺序加文本转换：`URL_DECODE`、`URL_DECODE`、`REMOVE_NULLS`、`NORMALIZE_PATH`、`LOWERCASE`
- 测试一下源站会不会对路径做解码。如果不解码，实际风险会低一些

---
""",
"path_only_allow": """## Issue {n} ({severity}): Allow 规则只按请求内容放行，没有 IP 等不可伪造的条件

**Rules**: {rule_line}
**Current state**: {rule_names} 只凭路径等请求内容就放行

**Problem**:
- 任何人只要知道或猜到路径，请求就能直达源站。Allow 会终止规则评估，后面的规则都不会再检查它
{acl_note}
**Recommendation**:
- 发送方公布了出口 IP 的，补上对应的 IP set 条件
- 拿不到出口 IP 的，应用层必须校验请求签名，并在 Allow 规则前面加上限定在这些路径的内容检测（CRS、KnownBadInputs）
- 路径尽量用 `EXACTLY`，或者把 `STARTS_WITH` 的值写得更具体

---
""",
"managed_count": """## Issue {n} (Medium): 托管规则的防护处于 Count

**Rules**: {rule_line}
**Current state**: 托管规则组整组，或组里的部分规则，被设成了 Count

**Problem**:
{details}
- Count 只记录指标和标签，不拦截。`SizeRestrictions_BODY` 保持 Count 是常见的合理做法，这里没有列出

**Recommendation**:
- 逐条查看 Count 期间的命中情况，再把规则切回默认动作
- 已确认在特定路径上有误报的规则，保持 Count，在规则组后面加一条自定义规则：匹配它的标签，并排除这些路径，动作设为 Block

---
""",
"bot_control_tgt_common": """## Issue {n} (Low): COMMON 级别下的 TGT_* override 不起作用

**Rule**: {rule_name} (priority {priority})
**Current state**: `InspectionLevel: COMMON`，配了 {count} 条 TGT_* override：{tgt_list}

**Problem**:
- TGT_* 规则只在 TARGETED 级别运行，这些 override 不会有任何效果

**Recommendation**:
- 删掉这些 override，或者明确决定改用 TARGETED。TARGETED 依赖 Challenge 或 JS/移动端 SDK 拿到的 token，不适合机器调用的 API

---
""",
}

