#!/usr/bin/env python3
"""WAF Generate Findings: Produce deterministic findings from pre-checks and flags.

Usage: python3 waf-generate-findings.py <output_dir> [--lang en|zh]
  output_dir: directory containing waf-summary.json and pre-checks.json
  --lang: output language (default: en)

Outputs:
  {output_dir}/scripted-findings.md   — Issue section Markdown
  {output_dir}/findings-metadata.json — structured metadata
"""
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

# ── Constants ──────────────────────────────────────────────────────────────

ALWAYS_LLM_SECTIONS = {5, 8, 17}
APPENDIX_ONLY_SECTIONS = {10}

SEVERITY_ORDER = {"Critical": 0, "Medium": 1, "Low": 2, "Awareness": 3}

RECOMMENDED_ORDER = [
    ("ip_allow", "IP whitelist/blacklist"),
    ("crawler_labeling", "Crawler labeling rule"),
    ("antiddos_amr", "AntiDDoS AMR"),
    ("ip_reputation", "IP reputation / Anonymous IP"),
    ("rate_based", "Rate-based rules"),
    ("custom_block_challenge", "Custom Block/Challenge rules"),
    ("always_on_challenge", "Always-on Challenge"),
    ("app_layer", "Application-layer rule groups (CRS, KnownBadInputs)"),
    ("bot_control", "Bot Control / ATP / ACFP"),
]

MANAGED_BASELINE_GROUPS = {
    "AWSManagedRulesCommonRuleSet": "CRS",
    "AWSManagedRulesKnownBadInputsRuleSet": "KnownBadInputs",
}

IP_REPUTATION_GROUPS = {
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesAnonymousIpList",
}

CRAWLER_LABEL_PATTERNS = ("crawler:", "custom:crawler")

NOT_APPLICABLE = "NOT_APPLICABLE"
AMBIGUOUS = "AMBIGUOUS"


# ── Helpers ────────────────────────────────────────────────────────────────

def _fatal(msg: str):
    print(f"Error: {msg}", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: FATAL")
    print(f"ACTION: FIX")
    print(f"CONTEXT: {msg}")
    sys.exit(2)


def _classify_rule_type(rule: dict) -> str:
    """Classify a rule into a recommended-order category."""
    mg = rule.get("managed")
    if mg:
        gn = mg.get("group_name", "")
        if "AntiDDoS" in gn:
            return "antiddos_amr"
        if "IpReputation" in gn or "AnonymousIp" in gn:
            return "ip_reputation"
        if "BotControl" in gn:
            return "bot_control"
        if "ATP" in gn or "ACFP" in gn:
            return "bot_control"
        if gn in MANAGED_BASELINE_GROUPS:
            return "app_layer"
        return "app_layer"
    if rule.get("type") == "rate_based":
        return "rate_based"
    # Custom rules
    if rule.get("action") == "allow":
        # IP-set-based Allow = ip_allow
        leaf_types = rule.get("statement", {}).get("leaf_types", [])
        if "ip_set" in leaf_types:
            return "ip_allow"
    if rule.get("action") in ("challenge", "captcha"):
        stmt = rule.get("statement", {}).get("summary", "")
        # Check if it's an always-on challenge (label-based challenge)
        if "label_match" in stmt:
            return "always_on_challenge"
    # Crawler labeling: Count + ASN + produces label
    if (rule.get("action") == "count" and
            "asn_match" in rule.get("statement", {}).get("leaf_types", [])):
        return "crawler_labeling"
    return "custom_block_challenge"


def _has_opaque_value(value: str) -> str:
    """Check if a string looks like a hash/secret. Returns 'yes', 'maybe', or 'no'."""
    if len(value) < 16:
        return "no"
    # Exclude common non-secret patterns
    if value.startswith("/"):  # URI paths
        return "no"
    if re.match(r'^[\w.-]+\.\w{2,}$', value):  # hostnames like example.com
        return "no"
    if value in ("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"):
        return "no"
    classes = 0
    if re.search(r'[a-z]', value):
        classes += 1
    if re.search(r'[A-Z]', value):
        classes += 1
    if re.search(r'[0-9]', value):
        classes += 1
    if re.search(r'[^a-zA-Z0-9]', value):
        classes += 1
    if classes >= 3:
        return "yes"
    if classes >= 2 and len(value) >= 24:
        return "maybe"
    return "no"


def _extract_exactly_values(summary: str) -> list[tuple[str, str]]:
    """Extract (field, value) pairs from EXACTLY matches in statement summary."""
    results = []
    for m in re.finditer(r"([\w:.-]+)\s+EXACTLY\s+'([^']*)'", summary):
        results.append((m.group(1), m.group(2)))
    return results


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
"missing_baseline": """## Issue {n} (Medium): Missing {missing_names} baseline protection rule groups

**Rule**: N/A (missing rule)
**Current state**: Web ACL does not contain {missing_names}

**Problem**:
- {missing_detail}
- The current Web ACL focuses on DDoS and Bot protection but lacks application-layer attack protection

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
- **Good**: deploy dual AMR instances in the same Web ACL — one for browser traffic (ChallengeAllDuringEvent enabled), one for API/native app traffic (Challenge disabled, Block sensitivity MEDIUM). See Appendix B for implementation steps
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
"managed_versions": """## Issue {n} (Low): {detail}

**Rule**: {rule_name} (priority {priority})
**Current state**: Using {current_version}

**Problem**:
- {version_problem}

**Recommendation**:
- {version_rec}
- Test in a staging environment before upgrading to confirm no increase in false positives

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
"priority_order": """## Issue {n} (Medium): Rule priority order issues — {summary}

**Rule**: Multiple rules
**Current state**: {current_state}

**Problem**:
{problems}

**Recommendation**:
- After cleaning up duplicate rules, reorganize priority order
- Recommended order (see Appendix D):
  1. Crawler labeling rule
  2. AntiDDoS AMR
  3. IP reputation + Anonymous IP
  4. Rate-based rules
  5. Custom Block/Challenge rules
  6. Landing Page Always-on Challenge
  7. Bot Control (last — per-request pricing, placing last minimizes cost)

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
"missing_baseline": """## Issue {n} (Medium): 缺少 {missing_names} 基线防护规则组

**Rule**: N/A（缺失规则）
**Current state**: Web ACL 中没有 {missing_names}

**Problem**:
- {missing_detail}
- 当前 Web ACL 专注于 DDoS 和 Bot 防护，但缺乏应用层攻击防护

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
- **推荐方案**：在同一 Web ACL 中部署双 AMR 实例——一个针对浏览器流量（启用 ChallengeAllDuringEvent），另一个针对 API/原生 App 流量（禁用 Challenge，Block 灵敏度 MEDIUM）。实现步骤见附录 B
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
"managed_versions": """## Issue {n} (Low): {detail}

**Rule**: {rule_name} (priority {priority})
**Current state**: 使用 {current_version}

**Problem**:
- {version_problem}

**Recommendation**:
- {version_rec}
- 升级前在测试环境验证，确认无误报增加

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
"priority_order": """## Issue {n} (Medium): 规则优先级顺序存在问题——{summary}

**Rule**: 多条规则
**Current state**: {current_state}

**Problem**:
{problems}

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
}

# ── Generators ─────────────────────────────────────────────────────────────
# Each returns (issue_md, metadata_dict) | NOT_APPLICABLE | AMBIGUOUS

def _gen_forgeable_allow(summary, pre_checks, flags, T, lang):
    allow_flags = flags.get("allow_rules", [])
    # Exclude rules handled by default_action_redundancy
    redundant_rule = None
    dar = pre_checks.get("default_action_redundancy", {})
    if dar.get("status") == "FAIL":
        redundant_rule = dar.get("rule")
    # Only handle all_forgeable + global blast radius
    candidates = [a for a in allow_flags
                  if a.get("all_forgeable") and a.get("blast_radius") == "global"
                  and a["name"] != redundant_rule]
    if not candidates:
        # If all Allow rules have unforgeable conditions, section is safe
        remaining = [a for a in allow_flags if a["name"] != redundant_rule]
        if not remaining:
            return NOT_APPLICABLE
        if all(not a.get("all_forgeable") for a in remaining):
            return NOT_APPLICABLE
        # Mixed forgeability within a group — needs LLM judgment
        return AMBIGUOUS

    # Group by forgeable_conditions content
    groups = defaultdict(list)
    for a in candidates:
        key = tuple(sorted(a.get("forgeable_conditions", [])))
        groups[key].append(a)

    results = []
    for key, group in groups.items():
        names = [a["name"] for a in group]
        rule_names = " / ".join(names)
        if len(group) == 1:
            rule_line = f"{names[0]} (priority {group[0]['priority']})"
            dup_note = ""
            dup_rec = ""
        else:
            rule_line = ", ".join(f"{a['name']} (priority {a['priority']})" for a in group)
            if lang == "zh":
                dup_note = f"- {len(group)} 条规则逻辑完全相同，只需保留一条\n"
                dup_rec = "- 删除重复规则，保留一条即可\n"
            else:
                dup_note = f"- {len(group)} rules have identical logic, only one is needed\n"
                dup_rec = "- Remove duplicate rules, keep one\n"

        fc = group[0]["forgeable_conditions"]
        forgeable_fields = ", ".join(fc)
        is_are = "is" if len(fc) == 1 else "are"
        # Build example
        if any("user-agent" in c for c in fc):
            forgeable_example = "the matching User-Agent header"
        elif any("header" in c for c in fc):
            forgeable_example = "the matching custom header"
        else:
            forgeable_example = "the matching condition"

        # Check for opaque/secret values in the statement (fix #1)
        opaque_note = ""
        opaque_rec = ""
        for a in group:
            for field, value in _extract_exactly_values(a.get("statement_summary", "")):
                if _has_opaque_value(value) == "yes":
                    truncated = value[:30] + "..." if len(value) > 30 else value
                    if lang == "zh":
                        opaque_note = f"- 匹配值 `{truncated}` 存储在 WAF 配置中，任何能读取 Web ACL 配置的人均可获取——泄露即意味着完全绕过 WAF\n"
                        opaque_rec = "- 定期轮换密钥值，并审计 WAF 配置的 IAM 访问权限\n"
                    else:
                        opaque_note = f"- The match value `{truncated}` is stored in the WAF configuration — anyone with read access to the Web ACL can obtain it, and a leaked value means full WAF bypass\n"
                        opaque_rec = "- Periodically rotate the secret value and audit IAM access to WAF configuration\n"
                    break
            if opaque_note:
                break

        md = T["forgeable_allow"].format(
            n="{n}", rule_names=rule_names, rule_line=rule_line,
            stmt_summary=group[0]["statement_summary"],
            forgeable_fields=forgeable_fields, is_are=is_are,
            forgeable_example=forgeable_example,
            dup_note=dup_note, dup_rec=dup_rec,
            opaque_note=opaque_note, opaque_rec=opaque_rec)
        results.append((md, {"severity": "Critical", "title_key": "forgeable_allow",
                             "rules": names, "sections": [1]}))
    return results if results else NOT_APPLICABLE


def _gen_hosting_provider_allow(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("hosting_provider_allow", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    md = T["hosting_provider_allow"].format(
        n="{n}", rule_name=check["rule"], priority=check["priority"])
    return [(md, {"severity": "Critical", "title_key": "hosting_provider_allow",
                  "rules": [check["rule"]], "sections": [7]})]


def _gen_scope_down_too_narrow(summary, pre_checks, flags, T, lang):
    scope_downs = flags.get("scope_downs", [])
    narrow = [s for s in scope_downs
              if s.get("scope_down_summary") == "uri_path EXACTLY '/'"
              and any(g in s.get("rule", "") for g in ("IpReputation", "AnonymousIp"))]
    if not narrow:
        # Check if IP reputation groups exist but have no scope-down
        return NOT_APPLICABLE
    rule_line = " and ".join(f"{s['rule']} (priority {s['priority']})" for s in narrow)
    md = T["scope_down_too_narrow"].format(n="{n}", rule_line=rule_line)
    return [(md, {"severity": "Medium", "title_key": "scope_down_too_narrow",
                  "rules": [s["rule"] for s in narrow], "sections": [2]})]


def _gen_challenge_on_post_api(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("challenge_on_post_api", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    rules = check.get("rules", [])
    rule_line = ", ".join(f"{r['name']} (priority {r['priority']})" for r in rules)
    # Check for duplicates
    dup_rec = ""
    names = [r["name"] for r in rules]
    md = T["challenge_on_post_api"].format(n="{n}", rule_line=rule_line, dup_rec=dup_rec)
    return [(md, {"severity": "Medium", "title_key": "challenge_on_post_api",
                  "rules": names, "sections": [4]})]


def _gen_missing_baseline(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    present = set()
    for r in rules:
        mg = r.get("managed")
        if mg:
            gn = mg.get("group_name", "")
            if gn in MANAGED_BASELINE_GROUPS:
                present.add(MANAGED_BASELINE_GROUPS[gn])
    missing = {"CRS", "KnownBadInputs"} - present
    if not missing:
        return NOT_APPLICABLE
    missing_names = " and ".join(sorted(missing))
    details = []
    recs = []
    if "CRS" in missing:
        if lang == "zh":
            details.append("CRS 提供 OWASP Top 10 防护（SQLi、XSS 等），是大多数 Web 应用的基础防护层")
            recs.append("- 评估是否需要添加 CRS；如果添加，务必将 `SizeRestrictions_Body` 覆盖为 Count，避免对大 payload 的 API 端点产生误报（实现步骤见附录 F）")
        else:
            details.append("CRS provides OWASP Top 10 protection (SQLi, XSS, etc.) — the baseline protection layer for most web applications")
            recs.append("- Evaluate whether to add CRS; if adding, override `SizeRestrictions_Body` to Count to avoid false positives on large-payload API endpoints (see Appendix F)")
    if "KnownBadInputs" in missing:
        if lang == "zh":
            details.append("KnownBadInputsRuleSet 防护 Log4Shell（CVE-2021-44228）、Java 反序列化漏洞等已知恶意输入模式，WCU 消耗低、误报率低")
            recs.append("- 添加 AWSManagedRulesKnownBadInputsRuleSet（WCU 消耗低，建议优先添加）")
        else:
            details.append("KnownBadInputsRuleSet protects against Log4Shell (CVE-2021-44228), Java deserialization exploits, and other known malicious input patterns — low WCU cost, low false positive rate")
            recs.append("- Add AWSManagedRulesKnownBadInputsRuleSet (low WCU cost, recommended as priority)")
    cap = summary.get("web_acl", {}).get("capacity")
    if cap is not None:
        if lang == "zh":
            recs.append(f"- 添加前请在 AWS 控制台确认剩余 WCU 容量（当前已使用 {cap} WCU，上限 5000）")
        else:
            recs.append(f"- Verify remaining WCU capacity in AWS Console before adding (current: {cap} / 5000)")
    md = T["missing_baseline"].format(
        n="{n}", missing_names=missing_names,
        missing_detail="\n- ".join(details), missing_rec="\n".join(recs))
    return [(md, {"severity": "Medium", "title_key": "missing_baseline",
                  "rules": [], "sections": [9]})]


def _gen_token_domain(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("token_domain", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    domains = check.get("domains", [])
    redundant = check.get("redundant", [])
    if not redundant:
        return NOT_APPLICABLE
    # Find apex
    apex = [d for d in domains if len(d.split(".")) == 2]
    apex_str = apex[0] if apex else domains[0]
    domain_list = ", ".join(f"`{d}`" for d in domains)
    md = T["token_domain"].format(n="{n}", domain_list=domain_list, apex=apex_str)
    return [(md, {"severity": "Low", "title_key": "token_domain",
                  "rules": [], "sections": [11]})]


def _gen_no_logging(summary, pre_checks, flags, T, lang):
    # WAF JSON exports typically don't include logging config.
    # We flag this as Awareness unconditionally — the LLM sanity check can override.
    md = T["no_logging"].format(n="{n}")
    return [(md, {"severity": "Awareness", "title_key": "no_logging",
                  "rules": [], "sections": [13]})]


def _gen_default_action_redundancy(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("default_action_redundancy", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    rule_name = check["rule"]
    priority = check["priority"]
    # Find statement summary
    stmt = ""
    for r in summary.get("rules", []):
        if r["name"] == rule_name:
            stmt = r.get("statement", {}).get("summary", "")
            break
    md = T["default_action_redundancy"].format(
        n="{n}", rule_name=rule_name, priority=priority, stmt_summary=stmt)
    return [(md, {"severity": "Low", "title_key": "default_action_redundancy",
                  "rules": [rule_name], "sections": [15]})]


def _gen_count_without_labels(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("count_without_labels", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    rules = check.get("rules", [])
    names = [r["name"] for r in rules]
    rule_names = " / ".join(names)
    rule_line = ", ".join(f"{r['name']} (priority {r['priority']})" for r in rules)
    # Check for duplicates within the group
    dup_note = ""
    dup_rec = ""
    if len(rules) > 1:
        if lang == "zh":
            dup_note = f"- {len(rules)} 条规则可能逻辑相同——请检查是否存在重复\n"
            dup_rec = "- 如果逻辑相同，删除重复规则\n"
        else:
            dup_note = f"- {len(rules)} rules may have identical logic — check if duplicates exist\n"
            dup_rec = "- Remove duplicate rules if logic is identical\n"
    md = T["count_without_labels"].format(
        n="{n}", rule_names=rule_names, rule_line=rule_line,
        dup_note=dup_note, dup_rec=dup_rec)
    return [(md, {"severity": "Awareness", "title_key": "count_without_labels",
                  "rules": names, "sections": [17]})]


def _gen_challenge_all_during_event(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    amr = None
    for r in rules:
        mg = r.get("managed")
        if mg and "AntiDDoS" in mg.get("group_name", ""):
            amr = r
            break
    if not amr:
        return NOT_APPLICABLE
    overrides = amr.get("managed", {}).get("overrides", [])
    disabled = any(o.get("rule_name") == "ChallengeAllDuringEvent" and o.get("action") == "count"
                   for o in overrides)
    if not disabled:
        return NOT_APPLICABLE
    cfg = amr.get("managed", {}).get("config", {})
    block_sens = cfg.get("sensitivity_to_block", "unknown")
    sens_map = {"LOW": ("high-suspicion", "medium and low-suspicion"),
                "MEDIUM": ("medium and high-suspicion", "low-suspicion"),
                "HIGH": ("all suspicion levels of", "no")}
    block_desc, remaining_desc = sens_map.get(block_sens, ("some", "remaining"))
    md = T["challenge_all_during_event"].format(
        n="{n}", rule_name=amr["name"], priority=amr["priority"],
        block_sens=block_sens, block_desc=block_desc, remaining_desc=remaining_desc)
    return [(md, {"severity": "Medium", "title_key": "challenge_all_during_event",
                  "rules": [amr["name"]], "sections": [3]})]


def _gen_unanchored_exempt_regex(summary, pre_checks, flags, T, lang):
    regex_flags = flags.get("exempt_regex_branches", [])
    if not regex_flags:
        return NOT_APPLICABLE
    results = []
    for rf in regex_flags:
        unanchored = [b for b in rf.get("branches", [])
                      if not b.get("anchored_start") and not b.get("anchored_end")]
        if not unanchored:
            continue
        unanchored_list = ", ".join(f"`{b['pattern']}`" for b in unanchored)
        examples = ", ".join(f"`/admin{b['pattern'].replace(chr(92), '')}/export`"
                             for b in unanchored[:2])
        anchored = "`" + "|".join(
            f"^{b['pattern']}" if not b.get("anchored_start") else b["pattern"]
            for b in rf["branches"]) + "`"
        md = T["unanchored_exempt_regex"].format(
            n="{n}", rule_name=rf["rule"], priority=rf["priority"],
            regex=rf["full_regex"], unanchored_list=unanchored_list,
            examples=examples, anchored_suggestion=anchored)
        results.append((md, {"severity": "Medium", "title_key": "unanchored_exempt_regex",
                             "rules": [rf["rule"]], "sections": [3]}))
    return results if results else NOT_APPLICABLE


def _gen_missing_crawler_labeling(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    has_amr = any("AntiDDoS" in r.get("managed", {}).get("group_name", "") for r in rules)
    if not has_amr:
        return NOT_APPLICABLE
    # Check for crawler labeling rule
    for r in rules:
        labels = r.get("rule_labels", [])
        for lbl in labels:
            if any(lbl.startswith(p) for p in CRAWLER_LABEL_PATTERNS):
                return NOT_APPLICABLE
        # Structural: Count + asn_match + produces any label
        if (r.get("action") == "count" and
                "asn_match" in r.get("statement", {}).get("leaf_types", []) and
                labels):
            return NOT_APPLICABLE
    md = T["missing_crawler_labeling"].format(n="{n}")
    return [(md, {"severity": "Medium", "title_key": "missing_crawler_labeling",
                  "rules": [], "sections": [3]})]


def _gen_bot_control_search_allow(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    for r in rules:
        mg = r.get("managed")
        if not mg or "BotControl" not in mg.get("group_name", ""):
            continue
        search_allows = [o for o in mg.get("overrides", [])
                         if o.get("action") == "allow" and
                         o.get("rule_name", "") in ("CategorySearchEngine", "CategorySeo")]
        if search_allows:
            override_names = " / ".join(o["rule_name"] for o in search_allows)
            md = T["bot_control_search_allow"].format(
                n="{n}", rule_name=r["name"], priority=r["priority"],
                override_names=override_names)
            return [(md, {"severity": "Low", "title_key": "bot_control_search_allow",
                          "rules": [r["name"]], "sections": [5]})]
    return NOT_APPLICABLE


def _gen_duplicate_rules(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    # Group rate-based rules
    rate_groups = defaultdict(list)
    for r in rules:
        if r.get("type") != "rate_based":
            continue
        rb = r.get("rate_based", {})
        sd = r.get("scope_down", {})
        sd_summary = sd.get("summary", "") if sd else ""
        key = (r["action"], rb.get("limit"), rb.get("evaluation_window_sec"), sd_summary)
        rate_groups[key].append(r)

    results = []
    all_dup_names = []
    all_pair_lines = []
    for key, group in rate_groups.items():
        if len(group) < 2:
            continue
        sorted_g = sorted(group, key=lambda x: x["priority"])
        for i in range(0, len(sorted_g) - 1, 2):
            all_pair_lines.append(f"{sorted_g[i]['name']} (P{sorted_g[i]['priority']}) / {sorted_g[i+1]['name']} (P{sorted_g[i+1]['priority']})")
        all_dup_names.extend(r["name"] for r in group)

    if not all_pair_lines:
        return NOT_APPLICABLE

    rule_line = "; ".join(all_pair_lines)
    pair_count = len(all_pair_lines)
    if lang == "zh":
        dup_problem = "对于 scope-down 重叠的速率限制规则，只有阈值最低的规则会对重叠流量生效——阈值更高的重复规则没有额外效果"
        match_desc = "scope-down、limit 和 window"
        rule_type = "速率限制"
    else:
        dup_problem = "For rate-based rules with overlapping scope-downs, only the lowest-threshold rule triggers for overlapping traffic — higher-threshold duplicates have no additional effect"
        match_desc = "scope-down, limit, and window"
        rule_type = "rate-limit "
    md = T["duplicate_rules"].format(
        n="{n}", rule_type=rule_type, rule_line=rule_line,
        pair_count=pair_count, match_desc=match_desc,
        dup_problem=dup_problem)
    results.append((md, {"severity": "Awareness", "title_key": "duplicate_rules",
                         "rules": all_dup_names, "sections": [6]}))
    return results


def _gen_managed_versions(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("managed_versions", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    results = []
    for detail_str in check.get("details", []):
        # Parse "rule_name: GroupName version X < Y (recommend upgrading)"
        parts = detail_str.split(":", 1)
        rule_name = parts[0].strip() if parts else "unknown"
        # Find rule
        priority = 0
        current_version = "unknown"
        for r in summary.get("rules", []):
            if r["name"] == rule_name:
                priority = r["priority"]
                current_version = r.get("managed", {}).get("version", "unknown")
                break
        if "BotControl" in detail_str:
            version_problem = "BotControlRuleSet Version_5.0 Common level can identify close to 700 bot types (based on UA and IP), far more than earlier versions"
            version_rec = "Upgrade BotControlRuleSet to Version_5.0"
            detail_en = f"Bot Control version outdated ({current_version}), recommend upgrading to 5.0"
            version_problem_zh = "BotControlRuleSet Version_5.0 的 Common level 可识别近 700 种 Bot 类型（基于 UA 和 IP），远超早期版本"
            version_rec_zh = "将 BotControlRuleSet 升级至 Version_5.0"
            detail_zh = f"Bot Control 版本过旧（{current_version}），建议升级至 5.0"
        elif "SQLi" in detail_str:
            version_problem = "SQLiRuleSet version 2.0 has significantly higher SQLi detection coverage than 1.0"
            version_rec = "Upgrade SQLiRuleSet to version 2.0"
            detail_en = f"SQLiRuleSet version outdated ({current_version}), recommend upgrading to 2.0"
            version_problem_zh = "SQLiRuleSet 2.0 版本的 SQLi 检测覆盖率显著高于 1.0"
            version_rec_zh = "将 SQLiRuleSet 升级至 2.0 版本"
            detail_zh = f"SQLiRuleSet 版本过旧（{current_version}），建议升级至 2.0"
        else:
            continue
        # Select language-appropriate strings
        if lang == "zh":
            detail, vp, vr = detail_zh, version_problem_zh, version_rec_zh
        else:
            detail, vp, vr = detail_en, version_problem, version_rec
        md = T["managed_versions"].format(
            n="{n}", detail=detail, rule_name=rule_name, priority=priority,
            current_version=current_version, version_problem=vp,
            version_rec=vr)
        results.append((md, {"severity": "Low", "title_key": "managed_versions",
                             "rules": [rule_name], "sections": [12]}))
    return results if results else NOT_APPLICABLE


def _gen_missing_always_on_challenge(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    has_amr = any("AntiDDoS" in r.get("managed", {}).get("group_name", "") for r in rules)
    if not has_amr:
        return NOT_APPLICABLE
    # Check for always-on challenge pattern
    # Pattern 1: Challenge rule consuming a label
    label_producers = {}
    for r in rules:
        for lbl in r.get("rule_labels", []):
            label_producers[lbl] = r["name"]
    for r in rules:
        if r.get("action") != "challenge" or r.get("type") != "custom":
            continue
        stmt = r.get("statement", {}).get("summary", "")
        # Check if it references a label
        label_refs = re.findall(r"label_match '([^']+)'", stmt)
        for lref in label_refs:
            if lref in label_producers:
                return NOT_APPLICABLE
    # Pattern 2: Challenge on landing page URIs directly
    landing_patterns = ("/", "/login", "/signup", "/register", "/index", "/home")
    for r in rules:
        if r.get("action") != "challenge" or r.get("type") != "custom":
            continue
        stmt = r.get("statement", {}).get("summary", "")
        if any(f"'{p}'" in stmt for p in landing_patterns):
            return NOT_APPLICABLE
    md = T["missing_always_on_challenge"].format(n="{n}")
    return [(md, {"severity": "Medium", "title_key": "missing_always_on_challenge",
                  "rules": [], "sections": [16]})]


def _gen_priority_order(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    if len(rules) < 2:
        return NOT_APPLICABLE
    # Classify each rule
    classified = [(r, _classify_rule_type(r)) for r in rules]
    order_index = {cat: i for i, (cat, _) in enumerate(RECOMMENDED_ORDER)}

    violations = []
    seen_cat_pairs = {}  # (cat1, cat2) -> (r1_name, r2_name) representative
    for i, (r1, cat1) in enumerate(classified):
        if cat1 not in order_index:
            continue
        for j in range(i + 1, len(classified)):
            r2, cat2 = classified[j]
            if cat2 not in order_index:
                continue
            if order_index[cat1] > order_index[cat2]:
                pair = (cat1, cat2)
                if pair not in seen_cat_pairs:
                    seen_cat_pairs[pair] = (r1, r2)

    for (cat1, cat2), (r1, r2) in seen_cat_pairs.items():
        desc1 = dict(RECOMMENDED_ORDER).get(cat1, cat1)
        desc2 = dict(RECOMMENDED_ORDER).get(cat2, cat2)
        violations.append(
            f"- {r1['name']} (P{r1['priority']}, {desc1}) is before "
            f"{r2['name']} (P{r2['priority']}, {desc2}), but recommended order is reversed")

    if not violations:
        return NOT_APPLICABLE
    if len(violations) > 8:
        violations = violations[:8]
        violations.append("- ... and more ordering issues")

    problems = "\n".join(violations)
    if lang == "zh":
        summary_text = f"发现 {len(violations)} 处顺序问题"
    else:
        summary_text = f"{len(violations)} ordering violations found"
    current_state = ", ".join(f"{r['name']} (P{r['priority']})" for r in rules[:5])
    if len(rules) > 5:
        current_state += f" ... ({len(rules)} rules total)"
    md = T["priority_order"].format(
        n="{n}", summary=summary_text, current_state=current_state, problems=problems)
    all_rules = [r["name"] for r in rules]
    return [(md, {"severity": "Medium", "title_key": "priority_order",
                  "rules": all_rules[:10], "sections": [18]})]


def _gen_opaque_search_string(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    # Skip rules already flagged as forgeable Allow (they get their own Critical finding)
    forgeable_allow_names = set()
    for a in flags.get("allow_rules", []):
        if a.get("all_forgeable") and a.get("blast_radius") == "global":
            forgeable_allow_names.add(a["name"])
    results = []
    seen_values = set()
    for r in rules:
        if r.get("type") != "custom":
            continue
        if r["name"] in forgeable_allow_names:
            continue
        stmt_summary = r.get("statement", {}).get("summary", "")
        for field, value in _extract_exactly_values(stmt_summary):
            if value in seen_values:
                continue
            opacity = _has_opaque_value(value)
            if opacity == "no":
                continue
            if opacity == "maybe":
                return AMBIGUOUS
            seen_values.add(value)
            is_allow = r.get("action") == "allow"
            if is_allow:
                risk_note = "Since this rule's action is Allow, a leaked value means full WAF bypass for anyone who knows it"
                rec_note = "If this is a shared secret for probe/monitoring access, switch to an unforgeable condition (IP Set or WAF Token)"
            else:
                risk_note = "This value may be a shared secret or redacted content"
                rec_note = "Verify whether this value is a secret that should be protected from exposure"
            md = T["opaque_search_string"].format(
                n="{n}", rule_name=r["name"], priority=r["priority"],
                stmt_summary=stmt_summary[:100], value=value[:30] + "..." if len(value) > 30 else value,
                risk_note=risk_note, rec_note=rec_note)
            results.append((md, {"severity": "Awareness", "title_key": "opaque_search_string",
                                 "rules": [r["name"]], "sections": [14]}))
    return results if results else NOT_APPLICABLE


def _gen_managed_allow_override(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    handled_rules = {"HostingProviderIPList", "CategorySearchEngine", "CategorySeo"}
    results = []
    for r in rules:
        mg = r.get("managed")
        if not mg:
            continue
        for o in mg.get("overrides", []):
            if o.get("action") == "allow" and o.get("rule_name", "") not in handled_rules:
                override_detail = f"`{o['rule_name']}` overridden to Allow"
                md = T["managed_allow_override"].format(
                    n="{n}", rule_name=r["name"], priority=r["priority"],
                    override_detail=override_detail)
                results.append((md, {"severity": "Awareness",
                                     "title_key": "managed_allow_override",
                                     "rules": [r["name"]], "sections": [1]}))
    return results if results else NOT_APPLICABLE


# ── Main ───────────────────────────────────────────────────────────────────

ALL_GENERATORS = [
    # (function, covered_sections, fully_covers_sections)
    (_gen_forgeable_allow, [1], True),
    (_gen_managed_allow_override, [1], True),
    (_gen_scope_down_too_narrow, [2], True),
    (_gen_challenge_all_during_event, [3], True),
    (_gen_unanchored_exempt_regex, [3], True),
    (_gen_missing_crawler_labeling, [3], True),
    (_gen_challenge_on_post_api, [4], True),
    (_gen_bot_control_search_allow, [5], False),  # Section 5 is always-LLM
    (_gen_duplicate_rules, [6], True),
    (_gen_hosting_provider_allow, [7], True),
    (_gen_missing_baseline, [9], True),
    (_gen_token_domain, [11], True),
    (_gen_managed_versions, [12], True),
    (_gen_no_logging, [13], True),
    (_gen_opaque_search_string, [14], True),
    (_gen_default_action_redundancy, [15], True),
    (_gen_missing_always_on_challenge, [16], True),
    (_gen_count_without_labels, [17], True),  # Covers 17a only; 17 is always-LLM
    (_gen_priority_order, [18], True),
]


def main():
    if len(sys.argv) < 2:
        _fatal("Usage: waf-generate-findings.py <output_dir> [--lang en|zh]")

    output_dir = sys.argv[1]
    lang = "en"
    if "--lang" in sys.argv:
        idx = sys.argv.index("--lang")
        if idx + 1 < len(sys.argv):
            lang = sys.argv[idx + 1]
    if lang not in ("en", "zh"):
        lang = "en"

    T = TEMPLATES_EN if lang == "en" else TEMPLATES_ZH

    summary_path = os.path.join(output_dir, "waf-summary.json")
    prechecks_path = os.path.join(output_dir, "pre-checks.json")

    if not os.path.isfile(summary_path):
        _fatal(f"waf-summary.json not found in {output_dir}")
    if not os.path.isfile(prechecks_path):
        _fatal(f"pre-checks.json not found in {output_dir}")

    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    pre_checks_data = json.loads(Path(prechecks_path).read_text(encoding="utf-8"))
    pre_checks = pre_checks_data.get("pre_checks", {})
    flags = pre_checks_data.get("flags", {})

    # Run all generators
    all_findings = []  # (md_template, metadata)
    section_outcomes = defaultdict(list)  # section -> list of (outcome_type, fully_covers)

    for gen_func, sections, fully_covers in ALL_GENERATORS:
        result = gen_func(summary, pre_checks, flags, T, lang)
        if result == NOT_APPLICABLE:
            for s in sections:
                section_outcomes[s].append(("not_applicable", fully_covers))
        elif result == AMBIGUOUS:
            for s in sections:
                section_outcomes[s].append(("ambiguous", fully_covers))
        else:
            # List of (md, metadata)
            for md, meta in result:
                all_findings.append((md, meta))
            for s in sections:
                section_outcomes[s].append(("finding", fully_covers))

    # Sort by severity then by first rule priority
    def sort_key(item):
        md, meta = item
        sev = SEVERITY_ORDER.get(meta["severity"], 99)
        # Get min priority from rules
        min_pri = 999
        for r in summary.get("rules", []):
            if r["name"] in meta.get("rules", []):
                min_pri = min(min_pri, r["priority"])
        return (sev, min_pri)

    all_findings.sort(key=sort_key)

    # Assign issue numbers
    findings_md = []
    scripted_issues = []
    issue_rule_mapping = {}

    for i, (md_template, meta) in enumerate(all_findings, 1):
        md = md_template.replace("{n}", str(i))
        findings_md.append(md)
        # Extract title from first line
        first_line = md.strip().split("\n")[0]
        title = first_line.split("): ", 1)[1] if "): " in first_line else first_line
        scripted_issues.append({
            "number": i,
            "severity": meta["severity"],
            "title": title.strip(),
            "rules": meta.get("rules", []),
            "checklist_sections": meta.get("sections", []),
        })
        for rule_name in meta.get("rules", []):
            if rule_name in issue_rule_mapping:
                issue_rule_mapping[rule_name] += f", #{i}"
            else:
                issue_rule_mapping[rule_name] = f"⚠️ Issue #{i}"

    # Compute llm_sections
    llm_sections = sorted(ALWAYS_LLM_SECTIONS)
    for s in range(1, 19):
        if s in ALWAYS_LLM_SECTIONS or s in APPENDIX_ONLY_SECTIONS:
            continue
        outcomes = section_outcomes.get(s, [])
        if not outcomes:
            # No generator covers this section — add to LLM
            llm_sections.append(s)
            continue
        # Check if any AMBIGUOUS from a fully-covering generator
        if any(otype == "ambiguous" and fc for otype, fc in outcomes):
            llm_sections.append(s)
            continue
        # Check if all fully-covering generators returned finding or not_applicable
        fully_covering = [(otype, fc) for otype, fc in outcomes if fc]
        if not fully_covering:
            # Only partial generators — section needs LLM
            llm_sections.append(s)
    llm_sections = sorted(set(llm_sections))

    # Compute llm_context
    rules = summary.get("rules", [])
    llm_context = {
        "ua_allow_found": any(
            "user-agent" in " ".join(a.get("forgeable_conditions", []))
            for a in flags.get("allow_rules", [])),
        "has_antiddos_amr": any(
            "AntiDDoS" in r.get("managed", {}).get("group_name", "") for r in rules),
        "has_bot_control": any(
            "BotControl" in r.get("managed", {}).get("group_name", "") for r in rules),
        "has_always_on_challenge": any(
            r.get("action") == "challenge" and r.get("type") == "custom" and
            "label_match" in r.get("statement", {}).get("summary", "")
            for r in rules),
        "has_crawler_labeling_rule": any(
            any(lbl.startswith(p) for p in CRAWLER_LABEL_PATTERNS)
            for r in rules for lbl in r.get("rule_labels", [])),
    }

    next_issue_number = len(all_findings) + 1

    # Write scripted-findings.md
    findings_path = os.path.join(output_dir, "scripted-findings.md")
    Path(findings_path).write_text("".join(findings_md), encoding="utf-8")

    # Write findings-metadata.json
    metadata = {
        "scripted_count": len(all_findings),
        "scripted_issues": scripted_issues,
        "issue_rule_mapping": issue_rule_mapping,
        "llm_sections": llm_sections,
        "llm_context": llm_context,
        "next_issue_number": next_issue_number,
        "lang": lang,
    }
    meta_path = os.path.join(output_dir, "findings-metadata.json")
    Path(meta_path).write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Generated {len(all_findings)} scripted findings ({lang}), "
          f"LLM sections: {llm_sections}", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"OUTPUT_FILE: {findings_path}")
    print(f"SCRIPTED_COUNT: {len(all_findings)}")
    print(f"LLM_SECTIONS: {','.join(str(s) for s in llm_sections)}")
    print(f"NEXT_ISSUE_NUMBER: {next_issue_number}")


if __name__ == "__main__":
    main()
