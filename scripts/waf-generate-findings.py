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
from waf_utils import fatal

# ── Constants ──────────────────────────────────────────────────────────────

ALWAYS_LLM_SECTIONS = {5, 8, 17}
APPENDIX_ONLY_SECTIONS = {10}

SEVERITY_ORDER = {"Critical": 0, "Medium": 1, "Low": 2, "Awareness": 3}

MANAGED_BASELINE_GROUPS = {
    "AWSManagedRulesCommonRuleSet": "CRS",
    "AWSManagedRulesKnownBadInputsRuleSet": "KnownBadInputs",
}

IP_REPUTATION_GROUPS = {
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesAnonymousIpList",
}

CRAWLER_LABEL_PATTERNS = ("crawler:", "custom:crawler")
# Host or path values that suggest a payment flow (checklist section 21)
PAYMENT_HINT = re.compile(r"pay|checkout|card|billing|3ds|wallet|merchant|psp", re.I)

AMR_GROUP = "AWSManagedRulesAntiDDoSRuleSet"
BOT_GROUP = "AWSManagedRulesBotControlRuleSet"

LINES = {
    "en": {
        "label_before_producer": "- {rules} matches label `{label}`, but every rule that adds it runs later: {others}. The condition never matches",
        "blocklist_after_allow": "- IP block list(s) {rules} run after Allow rules {others}. Requests those rules allow are never checked against the block list, so a listed IP that also matches them gets through",
        "inspection_after_allow": "- {group} rule group {rules} runs after Allow rules {others}. The default action is Block, so it only inspects traffic that would be blocked anyway. Traffic those Allow rules let through is never inspected",
        "bot_control_not_last": "- Bot Control {rules} runs before blocking rules {others}. Bot Control is charged per inspected request, so requests those rules block are paid for first. Cost only, no security impact",
        "rec_label_before_producer": "- Move the rule that adds the label ahead of the rule that matches it",
        "rec_blocklist_after_allow": "- Move IP block lists ahead of all Allow rules",
        "rec_inspection_after_allow": "- Move content inspection rule groups ahead of the Allow rules so allowed traffic is inspected first. Start in Count: partner payloads may trigger false positives",
        "rec_bot_control_not_last": "- Place Bot Control after rules that block requests on their own",
        "order_title": "{count} issue(s)",
        "rec_literal_wildcard": "- For wildcard intent, use a regex, or drop the `*` and keep `STARTS_WITH`",
        "rec_query_in_path": "- To match query parameters, use `QueryString` or `SingleQueryArgument` as the field to match",
        "wildcard": "- `{rule}` (priority {p}): `{value}` contains `*`. Byte match has no wildcards, so `*` is a literal character and this condition only matches paths that literally contain it",
        "query_in_path": "- `{rule}` (priority {p}): `{value}` expects a query string, but UriPath never includes the query string, so this condition never matches",
        "no_decode": "- `{rule}` (priority {p}): text transformation {transforms}{case}",
        "case_note": ". No LOWERCASE either, so a case change like `/Internal/` also gets through",
        "group_count": "- `{rule}` (priority {p}, {group}): the whole rule group is set to Count, none of its rules block",
        "rule_count": "- `{rule}` (priority {p}, {group}): {names} overridden to Count",
        "fragment_allow": "- For Allow rules this removes the path restriction: the rule allows every path for the requests its other conditions match",
        "default_block_note": "- This Web ACL blocks by default and relies on allow lists, so these rules are open entries into it\n",
        "sqli_lineage": "- `AWSManagedRulesSQLiRuleSet` has two version lineages with different detection trade-offs. The 2.0 line added JSON parsing to `SQLi_BODY`; 1.3, 2.3, 2.4, 2.5 form a separate line. Choose a lineage deliberately\n",
        "default_version": "AWS default (Version_1.0)",
        "unpinned_bot": "Bot Control is not pinned to a static version, so it runs the AWS default version, Version_1.0",
        "outdated_bot": "Bot Control is pinned to {version}",
        # What each static version added, from the AWS Managed Rules changelog
        "bot_versions": [
            ((2, 0), "- 2.0/3.0: the TARGETED `TGT_TokenReuse*` rules by IP, ASN, and country, and many new bot names across COMMON categories"),
            ((4, 0), "- 4.0: Web Bot Authentication, which verifies signed AI bots and agents (CloudFront only until 6.0)"),
            ((5, 0), "- 5.0: 400+ more bots, the `CategoryPagePreview` and `CategoryWebhooks` categories, and a precedence change so specific bot rules match before generic signals"),
            ((6, 0), "- 6.0: Web Bot Authentication on regional resources, and bots verified that way count as verified in every category"),
            ((6, 1), "- 6.1: more signatures across categories, including Security, SEO, and scraping frameworks"),
        ],
        "missing_amr": "- No Anti-DDoS rule group: this Web ACL allows traffic by default and has no automatic HTTP flood mitigation (Medium)",
        "missing_iprep": "- No Amazon IP reputation list: IPs on AWS threat intelligence lists, including ones doing reconnaissance and scanning, are not blocked (Medium)",
        "missing_anon": "- No anonymous IP list: traffic from VPNs, Tor, proxies, and non-AWS cloud hosts is not flagged. Many scanners run on cloud hosts (Low)",
        "missing_bot": "- No Bot Control: if this Web ACL serves browser pages, self-identifying bots and non-browser clients are not classified (Low)",
        "rec_amr": "- Anti-DDoS: add `AWSManagedRulesAntiDDoSRuleSet` at the top of the Web ACL, after IP allow lists. Don't scope it down. Exempt API and machine-to-machine paths from Challenge with the exempt URI regex",
        "rec_iprep": "- IP reputation: add `AWSManagedRulesAmazonIpReputationList` after Anti-DDoS, before rate-based and custom rules",
        "rec_anon": "- Anonymous IP: add `AWSManagedRulesAnonymousIpList` next to the IP reputation list, starting in Count. Scope it down to hosts or paths whose callers are end users: `HostingProviderIPList` blocks non-AWS cloud IPs and can block partners hosted there",
        "rec_bot": "- Bot Control: add it last in the Web ACL, pinned to the latest static version, scoped down to browser-facing hosts or paths",
        "placement_block": "- This Web ACL blocks by default: put the rule groups ahead of the Allow rules, or they never inspect the traffic those rules let through. Scope them down to paths that need inspection and start in Count",
        "placement_allow": "- Place them after IP reputation and rate-based rules",
        "example_ua": "the matching User-Agent header",
        "example_header": "the matching custom header",
        "example_other": "the matching condition",
        "hosting_scope_state": ", rule group scope-down `{scope}`",
        "hosting_scope": "- The rule group's scope-down is `{scope}`. Only requests that match it enter the rule group, so the bypass covers cloud-hosted requests that match the scope-down\n",
        "hosting_scope_widen": "- Before removing or widening that scope-down, change this override. Otherwise the bypass widens with it\n",
        "opaque_risk_allow": "Since this rule's action is Allow, a leaked value means full WAF bypass for anyone who knows it",
        "opaque_rec_allow": "If this is a shared secret for probe/monitoring access, switch to an unforgeable condition (IP Set or WAF Token)",
        "opaque_risk_other": "This value may be a shared secret or redacted content",
        "opaque_rec_other": "Verify whether this value is a secret that should be protected from exposure",
        "allow_override": "`{rule}` overridden to Allow",
        "levels": lambda lv: {1: "{}", 2: "{} and {}"}.get(len(lv), "{}, {}, and {}").format(*lv),
        "cade_block": "- `DDoSRequests` blocks {levels} suspicion requests (`sensitivity_to_block: {sens}`)",
        "cade_challenge": "- `ChallengeDDoSRequests` still challenges {levels} suspicion requests (challenge sensitivity `{sens}`). What's lost is the blanket challenge: during an event, challengeable requests the rule group hasn't marked as suspicious are no longer challenged",
        "cade_no_challenge": "- `ChallengeDDoSRequests` is off too ({why}), so nothing is challenged during an event",
        "why_cdr_count": "overridden to Count",
        "why_usage_disabled": "`usage_of_challenge_action: DISABLED`",
        "cade_gap": "- Requests with {levels} suspicion are neither challenged nor blocked",
    },
    "zh": {
        "label_before_producer": "- {rules}匹配标签 `{label}`，但产生这个标签的规则都排在它后面：{others}。这个条件永远不会成立",
        "blocklist_after_allow": "- IP 黑名单 {rules}排在 Allow 规则 {others} 后面。被这些规则放行的请求不会再经过黑名单，已经拉黑的 IP 只要同时命中这些 Allow 规则，就会被放行",
        "inspection_after_allow": "- {group} 规则组 {rules}排在 Allow 规则 {others} 后面。默认动作是 Block，它只检查到本来就会被拦的流量，被这些 Allow 规则放行的流量完全没有经过内容检测",
        "bot_control_not_last": "- Bot Control {rules}排在会拦截请求的规则 {others} 前面。Bot Control 按检查的请求数收费，这些规则拦下的请求已经先计过费了。这一条只影响费用，不影响安全",
        "rec_label_before_producer": "- 把产生标签的规则调到匹配该标签的规则前面",
        "rec_blocklist_after_allow": "- 把 IP 黑名单调到所有 Allow 规则前面",
        "rec_inspection_after_allow": "- 把内容检测规则组调到 Allow 规则前面，放行之前先检查。先用 Count 观察，合作方的回调 payload 可能会误报",
        "rec_bot_control_not_last": "- 把 Bot Control 放到这些拦截规则后面",
        "order_title": "发现 {count} 处",
        "rec_literal_wildcard": "- 想做通配匹配，改用正则，或者去掉 `*` 保留 `STARTS_WITH`",
        "rec_query_in_path": "- 想匹配查询参数，把匹配字段改成 `QueryString` 或 `SingleQueryArgument`",
        "wildcard": "- `{rule}`（priority {p}）：`{value}` 里有 `*`。字节匹配不支持通配符，`*` 就是一个普通字符，这个条件只会匹配路径里真的带 `*` 的请求",
        "query_in_path": "- `{rule}`（priority {p}）：`{value}` 要匹配的是查询串，但 UriPath 不包含查询串，这个条件永远不会命中",
        "no_decode": "- `{rule}`（priority {p}）：文本转换为 {transforms}{case}",
        "case_note": "。也没有做 LOWERCASE，改一下大小写（如 `/Internal/`）也能绕过",
        "group_count": "- `{rule}`（priority {p}，{group}）：整个规则组设成了 Count，组里的规则都不拦截",
        "rule_count": "- `{rule}`（priority {p}，{group}）：{names} 被改成了 Count",
        "fragment_allow": "- 对 Allow 规则来说，路径限制因此失效：只要其他条件满足，任何路径都会被放行",
        "default_block_note": "- 这个 ACL 默认 Block，靠白名单放行，这些规则等于在白名单上开了口子\n",
        "sqli_lineage": "- `AWSManagedRulesSQLiRuleSet` 分成两条版本线，检测逻辑不同。2.0 那条线给 `SQLi_BODY` 加了 JSON 解析；1.3、2.3、2.4、2.5 是另一条线。选版本时要明确选哪条线\n",
        "default_version": "AWS 默认版本（Version_1.0）",
        "unpinned_bot": "Bot Control 没有固定版本，跑的是 AWS 默认版本 Version_1.0",
        "outdated_bot": "Bot Control 固定在 {version}",
        "bot_versions": [
            ((2, 0), "- 2.0/3.0：TARGETED 级别按 IP、ASN、国家区分的 `TGT_TokenReuse*` 规则，COMMON 各类别也加了很多新的 bot"),
            ((4, 0), "- 4.0：Web Bot Authentication，用签名验证 AI bot 和 agent（6.0 之前只支持 CloudFront）"),
            ((5, 0), "- 5.0：新增 400 多种 bot，新增 `CategoryPagePreview` 和 `CategoryWebhooks` 两个类别，并调整了匹配顺序，具体的 bot 规则先于通用信号匹配"),
            ((6, 0), "- 6.0：Web Bot Authentication 支持区域资源，用这种方式验证过的 bot 在所有类别里都算已验证"),
            ((6, 1), "- 6.1：多个类别继续增加特征，包括 Security、SEO 和爬虫框架"),
        ],
        "missing_amr": "- 没有部署 Anti-DDoS 规则组：这个 ACL 默认放行，遇到 HTTP flood 时没有自动缓解（Medium）",
        "missing_iprep": "- 没有部署 Amazon IP 信誉列表：AWS 威胁情报名单上的 IP，包括正在做侦察和扫描的 IP，都不会被拦（Medium）",
        "missing_anon": "- 没有部署匿名 IP 列表：来自 VPN、Tor、代理和非 AWS 云主机的流量不会被标记。很多扫描器跑在云主机上（Low）",
        "missing_bot": "- 没有部署 Bot Control：如果这个 ACL 承载浏览器页面，自报身份的 bot 和非浏览器客户端都不会被分类（Low）",
        "rec_amr": "- Anti-DDoS：在 ACL 最前面（IP 白名单之后）加 `AWSManagedRulesAntiDDoSRuleSet`，不要加 scope-down。API 和机器调用的路径用豁免正则排除在 Challenge 之外",
        "rec_iprep": "- IP 信誉：`AWSManagedRulesAmazonIpReputationList` 放在 Anti-DDoS 之后、限速和自定义规则之前",
        "rec_anon": "- 匿名 IP：`AWSManagedRulesAnonymousIpList` 放在 IP 信誉列表旁边，先用 Count。用 scope-down 限定在调用方是最终用户的 host 或路径上：`HostingProviderIPList` 会拦非 AWS 的云主机 IP，可能误伤部署在其他云上的合作方",
        "rec_bot": "- Bot Control：放在 ACL 最后，固定到最新的静态版本，用 scope-down 限定在浏览器访问的 host 或路径上",
        "placement_block": "- 这个 ACL 默认 Block：规则组要放在 Allow 规则前面，否则检查不到被放行的流量。用 scope-down 限定在需要检查的路径上，先用 Count 观察",
        "placement_allow": "- 放在 IP 信誉和限速规则之后",
        "example_ua": "匹配的 User-Agent 头",
        "example_header": "匹配的自定义请求头",
        "example_other": "匹配的条件",
        "hosting_scope_state": "，规则组的 scope-down 为 `{scope}`",
        "hosting_scope": "- 规则组的 scope-down 是 `{scope}`，只有匹配它的请求才会进入规则组。所以被放行的是匹配这个 scope-down 的云主机请求\n",
        "hosting_scope_widen": "- 要去掉或放宽这个 scope-down，先改掉这个 override，否则放行范围会跟着扩大\n",
        "opaque_risk_allow": "这条规则的动作是 Allow，这个值一旦泄露，知道它的人就能完全绕过 WAF",
        "opaque_rec_allow": "如果这是给探针或监控用的共享密钥，改用不可伪造的条件（IP Set 或 WAF Token）",
        "opaque_risk_other": "这个值可能是共享密钥，也可能是脱敏后的内容",
        "opaque_rec_other": "确认这个值是不是需要保密的密钥",
        "allow_override": "`{rule}` 被覆盖为 Allow",
        "levels": lambda lv: "、".join({"low": "低", "medium": "中", "high": "高"}[x] for x in lv),
        "cade_block": "- `DDoSRequests` 会 Block 可疑度为{levels}的请求（`sensitivity_to_block: {sens}`）",
        "cade_challenge": "- `ChallengeDDoSRequests` 仍会 Challenge 可疑度为{levels}的请求（Challenge 灵敏度 `{sens}`）。少掉的是兜底的 Challenge：事件期间，没有被规则组标为可疑的可 Challenge 请求不再被 Challenge",
        "cade_no_challenge": "- `ChallengeDDoSRequests` 也没有生效（{why}），事件期间不会 Challenge 任何请求",
        "why_cdr_count": "被覆盖为 Count",
        "why_usage_disabled": "`usage_of_challenge_action: DISABLED`",
        "cade_gap": "- 可疑度为{levels}的请求既不会被 Challenge，也不会被 Block",
    },
}

SEVERITY_RANK = {"Critical": 0, "Medium": 1, "Low": 2, "Awareness": 3}


def _refs(items: list) -> str:
    return ", ".join(f"{i['name']} (priority {i['priority']})" for i in items)


def _ticks(items: list, lang: str = "en") -> str:
    return ("、" if lang == "zh" else ", ").join(f"`{i['name']}`" for i in items)


NOT_APPLICABLE = "NOT_APPLICABLE"
AMBIGUOUS = "AMBIGUOUS"


# ── Helpers ────────────────────────────────────────────────────────────────



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


def _payment_indicators(summary: dict) -> list:
    """Hosts, paths, and token domains that look like payment endpoints."""
    values = set(summary.get("web_acl", {}).get("token_domains") or [])
    for r in summary.get("rules", []):
        for l in r.get("statement", {}).get("leaves", []) + (r.get("scope_down") or {}).get("leaves", []):
            if (l["field"] in ("single_header:host", "uri_path") and isinstance(l["value"], str)
                    and not l["value"].startswith("arn:")):
                values.add(l["value"])
    return sorted(v for v in values if PAYMENT_HINT.search(v))[:20]

from waf_finding_templates import TEMPLATES_EN, TEMPLATES_ZH

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
        # If all Allow rules have unforgeable conditions, section is safe.
        # Path-scoped forgeable rules are reported by _gen_path_only_allow.
        remaining = [a for a in allow_flags if a["name"] != redundant_rule
                     and not (a.get("all_forgeable") and a.get("blast_radius") == "path_scoped")]
        if not remaining:
            return NOT_APPLICABLE
        if all(not a.get("all_forgeable") for a in remaining):
            return NOT_APPLICABLE
        # Mixed forgeability within a group — needs LLM judgment
        return AMBIGUOUS

    L = LINES[lang]
    # Group by forgeable_conditions content
    groups = defaultdict(list)
    for a in candidates:
        key = tuple(sorted(a.get("forgeable_conditions", [])))
        groups[key].append(a)

    results = []
    for key, group in groups.items():
        names = [a["name"] for a in group]
        rule_names = " / ".join(names)
        rule_line = _refs(group)

        fc = group[0]["forgeable_conditions"]
        forgeable_fields = ", ".join(fc)
        is_are = "is" if len(fc) == 1 else "are"
        if any("user-agent" in c for c in fc):
            forgeable_example = L["example_ua"]
        elif any("header" in c for c in fc):
            forgeable_example = L["example_header"]
        else:
            forgeable_example = L["example_other"]

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
            opaque_note=opaque_note, opaque_rec=opaque_rec)
        results.append((md, {"severity": "Critical", "title_key": "forgeable_allow",
                             "rules": names, "sections": [1]}))
    return results if results else NOT_APPLICABLE


def _gen_hosting_provider_allow(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("hosting_provider_allow", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    L = LINES[lang]
    sd = check.get("scope_down")
    scope_note = ""
    if sd:
        scope_note = L["hosting_scope"].format(scope=sd)
        if check.get("path_scoped"):
            scope_note += L["hosting_scope_widen"]
    # A path scope-down limits the bypass to requests on those paths
    severity = "Medium" if check.get("path_scoped") else "Critical"
    md = T["hosting_provider_allow"].format(
        n="{n}", severity=severity, rule_name=check["rule"], priority=check["priority"],
        scope_state=L["hosting_scope_state"].format(scope=sd) if sd else "",
        scope_note=scope_note)
    return [(md, {"severity": severity, "title_key": "hosting_provider_allow",
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
    missing_names = (" 和 " if lang == "zh" else " and ").join(sorted(missing))
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
    default_block = summary.get("web_acl", {}).get("default_action") == "block"
    recs.append(LINES[lang]["placement_block" if default_block else "placement_allow"])
    cap = summary.get("web_acl", {}).get("capacity")
    if cap is not None:
        if lang == "zh":
            recs.append(f"- 添加前请在 AWS 控制台确认剩余 WCU 容量（当前已使用 {cap} WCU，上限 5000）")
        else:
            recs.append(f"- Verify remaining WCU capacity in AWS Console before adding (current: {cap} / 5000)")
    # In an allow-list ACL, content inspection is defense in depth only
    severity = "Low" if default_block else "Medium"
    md = T["missing_baseline"].format(
        n="{n}", severity=severity, missing_names=missing_names,
        missing_detail="\n- ".join(details), missing_rec="\n".join(recs))
    return [(md, {"severity": severity, "title_key": "missing_baseline",
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
    # Web ACL JSON never includes logging config; waf-preprocess.py --logging supplies it.
    status = summary.get("web_acl", {}).get("logging", {}).get("status", "unknown")
    if status == "enabled":
        return NOT_APPLICABLE
    key = "logging_disabled" if status == "disabled" else "no_logging"
    md = T[key].format(n="{n}")
    return [(md, {"severity": "Awareness", "title_key": key,
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
    md = T["count_without_labels"].format(
        n="{n}", rule_names=rule_names, rule_line=_refs(rules))
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
    cfg = amr.get("managed", {}).get("config") or {}
    L = LINES[lang]
    # Suspicion levels each sensitivity setting acts on
    levels = {"LOW": ["high"], "MEDIUM": ["medium", "high"], "HIGH": ["low", "medium", "high"]}
    block_sens = cfg.get("sensitivity_to_block", "LOW")
    challenge_sens = cfg.get("sensitivity_to_challenge", "HIGH")
    blocked = levels.get(block_sens, [])
    details = [L["cade_block"].format(levels=L["levels"](blocked), sens=block_sens)]
    cdr_count = any(o.get("rule_name") == "ChallengeDDoSRequests" and o.get("action") == "count"
                    for o in overrides)
    if cfg.get("usage_of_challenge_action") == "DISABLED" or cdr_count:
        challenged = []
        details.append(L["cade_no_challenge"].format(
            why=L["why_cdr_count"] if cdr_count else L["why_usage_disabled"]))
    else:
        challenged = levels.get(challenge_sens, [])
        details.append(L["cade_challenge"].format(levels=L["levels"](challenged), sens=challenge_sens))
    gap = [lv for lv in ("low", "medium", "high") if lv not in blocked + challenged]
    if gap:
        details.append(L["cade_gap"].format(levels=L["levels"](gap)))
    # Medium only if some suspicion level gets neither Challenge nor Block
    severity = "Medium" if gap else "Low"
    md = T["challenge_all_during_event"].format(
        n="{n}", severity=severity, rule_name=amr["name"], priority=amr["priority"],
        details="\n".join(details))
    return [(md, {"severity": severity, "title_key": "challenge_all_during_event",
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
        examples = ", ".join(f"`/admin{b['pattern'].replace(chr(92), '').rstrip('/')}/export`"
                             for b in unanchored[:2])
        anchored = "`" + "|".join(
            f"^{b['pattern']}" if not (b.get("anchored_start") or b.get("anchored_end"))
            else b["pattern"]
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
    check = pre_checks.get("duplicate_rules", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    groups = check["groups"]
    fmt = "`{}`（priority {}）" if lang == "zh" else "`{}` (priority {})"
    lines = "\n".join("- " + " / ".join(fmt.format(r["name"], r["priority"]) for r in g)
                      for g in groups)
    rules = [r for g in groups for r in g]
    md = T["duplicate_rules"].format(n="{n}", count=len(groups), rule_line=_refs(rules),
                                     groups=lines)
    return [(md, {"severity": "Low", "title_key": "duplicate_rules",
                  "rules": [r["name"] for r in rules], "sections": [6]})]


def _gen_managed_versions(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("managed_versions", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    L = LINES[lang]
    results = []
    bots = [u for u in check.get("unpinned", []) if u["group"] == BOT_GROUP]
    bots += [o for o in check.get("outdated", []) if o["group"] == BOT_GROUP]
    for b in bots:
        version = b.get("version") or L["default_version"]
        detail = L["outdated_bot"].format(version=b["version"]) if b.get("version") else L["unpinned_bot"]
        m = re.search(r'(\d+)\.(\d+)', b.get("version") or "1.0")
        current = (int(m.group(1)), int(m.group(2))) if m else (1, 0)
        additions = "\n".join("  " + line for v, line in L["bot_versions"] if v > current)
        md = T["bot_control_version"].format(
            n="{n}", rule_name=b["name"], priority=b["priority"],
            current_version=version, detail=detail, additions=additions)
        results.append((md, {"severity": "Medium", "title_key": "bot_control_version",
                             "rules": [b["name"]], "sections": [12]}))
    others = [u for u in check.get("unpinned", []) if u["group"] != BOT_GROUP]
    if others:
        sqli_note = L["sqli_lineage"] if any("SQLi" in u["group"] for u in others) else ""
        md = T["managed_unpinned"].format(
            n="{n}", rule_line=_refs(others),
            groups=", ".join(f"`{u['group']}`" for u in others), sqli_note=sqli_note)
        results.append((md, {"severity": "Low", "title_key": "managed_unpinned",
                             "rules": [u["name"] for u in others], "sections": [12]}))
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


def _gen_order_issues(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("order_issues", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    L = LINES[lang]
    # Merge issues of the same kind that share the same counterpart rules
    merged = {}
    for i in check["issues"]:
        others = i.get("producers") or i.get("allows") or i.get("later") or []
        key = (i["kind"], i.get("label", ""), i.get("group", ""), tuple(o["name"] for o in others))
        merged.setdefault(key, {"issue": i, "others": others, "subjects": []})["subjects"].append(i["rule"])
    fmt = "`{}`（priority {}）" if lang == "zh" else "`{}` (priority {})"
    sep = "、" if lang == "zh" else ", "
    problems, kinds = [], []
    for (kind, label, group, _), m in merged.items():
        problems.append(L[kind].format(
            rules=sep.join(fmt.format(r["name"], r["priority"]) for r in m["subjects"]),
            label=label, group=group, others=_ticks(m["others"], lang)))
        if kind not in kinds:
            kinds.append(kind)
    recs = "\n".join(L["rec_" + k] for k in kinds)
    # Cost-only findings are Low; anything that changes what gets inspected is Medium
    severity = "Low" if kinds == ["bot_control_not_last"] else "Medium"
    md = T["order_issues"].format(
        n="{n}", severity=severity, summary=L["order_title"].format(count=len(problems)),
        rule_line=_refs(check["rules"]), problems="\n".join(problems), recs=recs)
    return [(md, {"severity": severity, "title_key": "order_issues",
                  "rules": [r["name"] for r in check["rules"]], "sections": [18]})]


def _gen_recommended_protections(summary, pre_checks, flags, T, lang):
    """Best-practice protections missing from an internet-facing (default Allow)
    Web ACL. Allow-list ACLs already block unknown traffic, so these don't apply."""
    if summary.get("web_acl", {}).get("default_action") != "allow":
        return NOT_APPLICABLE
    groups = {(r.get("managed") or {}).get("group_name", "") for r in summary.get("rules", [])}
    L = LINES[lang]
    items = []  # (key, severity)
    if AMR_GROUP not in groups:
        items.append(("amr", "Medium"))
    if "AWSManagedRulesAmazonIpReputationList" not in groups:
        items.append(("iprep", "Medium"))
    if "AWSManagedRulesAnonymousIpList" not in groups:
        items.append(("anon", "Low"))
    if BOT_GROUP not in groups:
        items.append(("bot", "Low"))
    if not items:
        return NOT_APPLICABLE
    names = {"amr": "Anti-DDoS AMR", "iprep": "Amazon IP reputation list",
             "anon": "Anonymous IP list", "bot": "Bot Control"}
    if lang == "zh":
        names.update(iprep="Amazon IP 信誉列表", anon="匿名 IP 列表")
    severity = min((sev for _, sev in items), key=SEVERITY_RANK.get)
    md = T["recommended_protections"].format(
        n="{n}", severity=severity, names=("、" if lang == "zh" else ", ").join(names[k] for k, _ in items),
        problems="\n".join(L["missing_" + k] for k, _ in items),
        recs="\n".join(L["rec_" + k] for k, _ in items))
    return [(md, {"severity": severity, "title_key": "recommended_protections",
                  "rules": [], "sections": [3, 5, 7]})]


def _gen_uri_fragment_fallback(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("uri_fragment_fallback", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    rules = check["rules"]
    has_allow = any(r["action"] == "allow" for r in rules)
    severity = "Critical" if has_allow else "Medium"
    md = T["uri_fragment_fallback"].format(
        n="{n}", severity=severity, rule_line=_refs(rules), rule_names=_ticks(rules, lang),
        allow_note=LINES[lang]["fragment_allow"] if has_allow else "")
    return [(md, {"severity": severity, "title_key": "uri_fragment_fallback",
                  "rules": [r["name"] for r in rules], "sections": [1, 19]})]


def _gen_uri_path_pitfalls(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("uri_path_pitfalls", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    L = LINES[lang]
    details = []
    for r in check["rules"]:
        for pb in r["problems"]:
            key = "wildcard" if pb["kind"] == "literal_wildcard" else "query_in_path"
            details.append(L[key].format(rule=r["name"], p=r["priority"], value=pb["value"]))
    kinds = {pb["kind"] for r in check["rules"] for pb in r["problems"]}
    recs = [L["rec_" + k] for k in ("literal_wildcard", "query_in_path") if k in kinds]
    md = T["uri_path_pitfalls"].format(
        n="{n}", rule_line=_refs(check["rules"]), details="\n".join(details),
        recs="\n".join(recs))
    return [(md, {"severity": "Medium", "title_key": "uri_path_pitfalls",
                  "rules": [r["name"] for r in check["rules"]], "sections": [19]})]


def _gen_path_block_decoding(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("path_block_decoding", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    L = LINES[lang]
    details = [L["no_decode"].format(
        rule=r["name"], p=r["priority"],
        transforms=" / ".join(f"`{t}`" for t in r["transforms"]),
        case=L["case_note"] if r["case_sensitive"] else "") for r in check["rules"]]
    md = T["path_block_decoding"].format(
        n="{n}", rule_line=_refs(check["rules"]), details="\n".join(details))
    return [(md, {"severity": "Medium", "title_key": "path_block_decoding",
                  "rules": [r["name"] for r in check["rules"]], "sections": [19]})]


def _gen_path_only_allow(summary, pre_checks, flags, T, lang):
    """Path-scoped Allow rules whose conditions are all forgeable (no IP set,
    label, or other unforgeable condition). Global ones are forgeable_allow."""
    rules = [a for a in flags.get("allow_rules", [])
             if a.get("all_forgeable") and a.get("blast_radius") == "path_scoped"]
    if not rules:
        return NOT_APPLICABLE
    default_block = summary.get("web_acl", {}).get("default_action") == "block"
    severity = "Critical" if default_block else "Medium"
    md = T["path_only_allow"].format(
        n="{n}", severity=severity, rule_line=_refs(rules), rule_names=_ticks(rules, lang),
        acl_note=LINES[lang]["default_block_note"] if default_block else "")
    return [(md, {"severity": severity, "title_key": "path_only_allow",
                  "rules": [r["name"] for r in rules], "sections": [1]})]


def _gen_managed_count(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("managed_count", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    L = LINES[lang]
    details = [L["group_count"].format(rule=g["name"], p=g["priority"], group=g["group"])
               for g in check.get("groups", [])]
    details += [L["rule_count"].format(rule=o["name"], p=o["priority"], group=o["group"],
                                       names=", ".join(f"`{x}`" for x in o["overridden"]))
                for o in check.get("overrides", [])]
    md = T["managed_count"].format(
        n="{n}", rule_line=_refs(check["rules"]), details="\n".join(details))
    return [(md, {"severity": "Medium", "title_key": "managed_count",
                  "rules": [r["name"] for r in check["rules"]], "sections": [20]})]


def _gen_bot_control_config(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("bot_control_config", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    tgt = check["tgt_overrides"]
    md = T["bot_control_tgt_common"].format(
        n="{n}", rule_name=check["rule"], priority=check["priority"],
        count=len(tgt), tgt_list=", ".join(f"`{t}`" for t in tgt))
    return [(md, {"severity": "Low", "title_key": "bot_control_tgt_common",
                  "rules": [check["rule"]], "sections": [5]})]


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
            kind = "allow" if r.get("action") == "allow" else "other"
            risk_note = LINES[lang]["opaque_risk_" + kind]
            rec_note = LINES[lang]["opaque_rec_" + kind]
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
                override_detail = LINES[lang]["allow_override"].format(rule=o["rule_name"])
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
    (_gen_order_issues, [18], True),
    (_gen_recommended_protections, [3, 5, 7], False),
    (_gen_uri_fragment_fallback, [1, 19], True),
    (_gen_path_only_allow, [1], True),
    (_gen_uri_path_pitfalls, [19], True),
    (_gen_path_block_decoding, [19], True),
    (_gen_managed_count, [20], True),
    (_gen_bot_control_config, [5], False),
]


def main():
    if len(sys.argv) < 2:
        fatal("Usage: waf-generate-findings.py <output_dir> [--lang en|zh]")

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
        fatal(f"waf-summary.json not found in {output_dir}")
    if not os.path.isfile(prechecks_path):
        fatal(f"pre-checks.json not found in {output_dir}")

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
    for s in range(1, 22):
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
        "payment_indicators": _payment_indicators(summary),
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
