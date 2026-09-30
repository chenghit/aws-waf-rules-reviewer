#!/usr/bin/env python3
"""WAF Generate Findings: Produce deterministic findings from pre-checks and flags.

Usage: python3 waf-generate-findings.py <output_dir> [--lang en|zh]
  output_dir: directory containing waf-summary.json and pre-checks.json
  --lang: output language (default: en)

Outputs:
  {output_dir}/scripted-findings.md   : Issue section Markdown
  {output_dir}/findings-metadata.json : structured metadata
"""
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from waf_utils import fatal, work_path

# ── Constants ──────────────────────────────────────────────────────────────

ALWAYS_LLM_SECTIONS = {5, 8, 17}
APPENDIX_ONLY_SECTIONS = {10}
RETIRED_SECTIONS = {14}  # hashed search_string: now judged by forgeability in section 1

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
        "bot_control_not_last": "- Bot Control {rules} runs before rules that block or challenge requests on their own: {others}. Bot Control is charged per inspected request, so requests those rules stop are paid for first. Cost only, no security impact",
        "label_no_producer": "- {rules} matches label `{label}`, but no rule in this Web ACL adds it. The condition never matches",
        "unreachable": "- {rules} never sees a request: every request it matches has already been ended by {others} ({actions})",
        "rec_label_before_producer": "- Move the rule that adds the label ahead of the rule that matches it",
        "rec_blocklist_after_allow": "- Move IP block lists ahead of all Allow rules",
        "rec_inspection_after_allow": "- Move content inspection rule groups ahead of the Allow rules so allowed traffic is inspected first. Start in Count and check for false positives before switching to the default actions",
        "rec_bot_control_not_last": "- Place Bot Control after rules that block or challenge requests on their own",
        "rec_label_no_producer": "- Check the label name. If the rule that added it was removed, remove or rewrite this condition",
        "rec_unreachable": "- Decide which rule should handle this traffic: narrow the earlier rule's condition, or remove the later rule",
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
        "rec_amr": "- Anti-DDoS: add `AWSManagedRulesAntiDDoSRuleSet` at the top of the Web ACL, after Allow rules that match only IP sets and after the crawler labeling rule (Appendix A). Don't scope it down to a few paths: it needs all traffic for its baseline (the two-instance split in Appendix B is the exception). Exempt API and machine-to-machine paths from Challenge with the exempt URI regex",
        "rec_iprep": "- IP reputation: add `AWSManagedRulesAmazonIpReputationList` after Anti-DDoS, before rate-based and custom rules",
        "rec_anon": "- Anonymous IP: add `AWSManagedRulesAnonymousIpList` next to the IP reputation list, starting in Count. Scope it down to hosts or paths whose callers are end users: `HostingProviderIPList` blocks non-AWS cloud IPs and can block partners hosted there",
        "rec_bot": "- Bot Control: add it last in the Web ACL, pinned to the latest static version, scoped down to browser-facing hosts or paths",
        "placement_block": "- This Web ACL blocks by default: put the rule groups ahead of the Allow rules, or they never inspect the traffic those rules let through. Scope them down to paths that need inspection and start in Count",
        "placement_allow": "- Place them after IP reputation and rate-based rules",
        "example_ua": "the matching User-Agent",
        "example_header": "the matching header",
        "example_cookie": "the matching cookie",
        "example_query": "the matching query argument",
        "example_other": "the matching value",
        "sum_managed": "- {k} rule(s) across {g} managed rule group(s) are in Count: they label but don't block{whole}",
        "sum_whole": ". {names} block nothing at all",
        "sum_order": "- {n} ordering problem(s) that change what gets inspected or blocked: {kinds}",
        "kind_label_before_producer": "a label used before it's added",
        "kind_label_no_producer": "a label nothing adds",
        "kind_blocklist_after_allow": "a block list after Allow rules",
        "kind_inspection_after_allow": "content inspection after Allow rules",
        "kind_unreachable": "{c} rule(s) no request reaches",
        "kind_after_last_allow": "{c} rule(s) that can't change the outcome",
        "kind_bot_control_not_last": "Bot Control billed before blocking rules",
        "sum_exempt": "- {n} rule(s) skip requests that carry a value any client can send ({fields})",
        "sum_dead": "- {n} pattern(s) in {r} rule(s) can never match, so those conditions don't do what they were written for",
        "sum_noop": "- {n} override(s) set a rule to the action it already has, and change nothing",
        "sum_rate_challenge": "- {n} rate limit(s) act with Challenge or CAPTCHA, so a client with a valid token isn't limited",
        "sum_rate_shared": "- {n} rate limit(s) put every matching client in one count, so forged requests can use it up",
        "sum_unused": "- {n} rule(s) add labels that no rule uses",
        "sum_uri": "- {n} URI path condition(s) can never match as written",
        "or_join": " or ",
        "f_header": "the `{name}` header",
        "f_cookie": "the `{name}` cookie",
        "f_cookies": "cookies",
        "f_query_arg": "the `{name}` query argument",
        "f_query": "the query string",
        "f_body": "the request body",
        "or_note": "- The rule ORs these conditions with {safe}. Any one branch is enough to match, so the {safe} condition doesn't limit the forgeable ones\n",
        "or_rec": "- Keep only the {safe} conditions in this Allow rule and remove the forgeable branches\n",
        "path_note": "- Branches limited to {paths} also let forged requests through on those paths\n",
        "path_open": "- Branches limited to {paths} let every request to those paths through, forged or not\n",
        "skipped": ", including every rule that could stop the request ({rules})",
        "skipped_more": "{total} of them: {rules}, and {k} more",
        "skipped_default": ". The default action is Block, so this rule is also the way in: anyone who sends the value gets through",
        "rec_count_label": "- If the traffic needs to be identified, use a Count+Label rule (e.g., `custom:native-app` or `custom:probe`) instead of Allow. It doesn't need to bypass the WAF entirely\n",
        "rec_unforgeable": "- For internal probes, monitoring, or testers, use an unforgeable condition instead, such as an IP set\n",
        "rec_default_block": "- This Web ACL blocks by default, so a Count+Label rule wouldn't let this traffic in. Give access by source IP instead: an IP set, reached through the office network or a VPN. A WAF token doesn't work as access control, since any browser can get one\n",
        "rec_crawler": "- For search engine crawlers, use the ASN + User-Agent labeling rule in Appendix A and exclude its `crawler:verified` label where needed, instead of allowing a User-Agent\n",
        "exemption": "- `{rule}` (priority {p}): requests where {field} {match} `{value}` skip {what}",
        "what_managed_rule_group": "the whole rule group",
        "what_rate_based": "the rate limit",
        "what_custom": "this rule",
        "case_dead": "- `{rule}` (priority {p}): after {transform}, {field} can't contain {dead}{whole}{neg}",
        "case_whole": ". The condition never matches",
        "case_neg": ". It sits under a NOT, so the exclusion never applies",
        "case_neg_part": ". It sits under a NOT, so these requests aren't excluded",
        "case_rec": "- Write these patterns in the case the transform produces, e.g. `adsbot-google` after LOWERCASE",
        "case_rec_allow": "- `{rule}` is a forgeable Allow: don't fix the pattern there, since that widens the Allow. Removing the forgeable branch fixes both",
        "case_why": "- WAF applies text transformations before matching, so after LOWERCASE the input has no uppercase letters left (and the reverse for UPPERCASE)",
        "crawler_dead_ua": "- `{rule}` (priority {p}): {dead} matches none of the User-Agents {family} publishes{whole}{neg}",
        "crawler_dead_robots": "- `{rule}` (priority {p}): {dead} is a robots.txt name only; {family} says it never appears in the User-Agent, so the branch does nothing{whole}{neg}",
        "dead_rec_ua": "- These are crawler conditions on the User-Agent, which any client can send even once the pattern is right. Identify crawlers with the `crawler:verified` label from the ASN + User-Agent rule in Appendix A instead. If you keep the User-Agent condition for now, write each name the way the crawler sends it: lowercase after LOWERCASE, and `bingbot` rather than `bingbot.html`",
        "exempt_count": " (the rule is in Count today; this matters once it switches to its intended action)",
        "exempt_label": " (it's a Count+Label rule: those requests don't get its label, so the rules acting on that label skip them too)",
        "exempt_default_block": " (the Web ACL blocks by default and no later rule allows, so skipping it doesn't change the outcome today)",
        "exempt_browser": " (a prefetch can't solve a Challenge, so this exemption is usually deliberate)",
        "exempt_browser_rec": "- For browser prefetch exemptions, limit them to GET requests for the pages that are prefetched, and keep a rate limit that doesn't exempt them\n",
        "still_blocking": "; only {names} still blocks, and only if the running version has it",
        "still_blocking_now": "; only {names} still blocks",
        "all_counted": "; every rule of the group is in Count, so it only labels",
        "noop": "- `{rule}` (priority {p}, {group}): {names}, each the rule's default action",
        "rate_challenge": "- `{rule}` (priority {p}): {action} at {limit} requests. A client with a valid token passes however fast it sends, for {immunity} seconds after each solve",
        "rate_shared": "- `{rule}` (priority {p}): counted by `{key}`, {limit} requests per {window} seconds. Every client that matches adds to the same count, so one client can push everyone sharing that value over the limit",
        "unused_label": "- `{rule}` (priority {p}, {action}): adds {labels}, which no rule matches",
        "rate_rec_shared": "- Add the IP to the aggregation keys, or confirm that one shared budget for everyone with that value is what you want\n",
        "rate_shared_crawler": "- `{rule}` (priority {p}): one budget of {limit} requests per {window} seconds for everything with this User-Agent (`{key}`), which search engine crawlers also send. Anyone can send that User-Agent, so forged requests use up the budget and the real crawler gets blocked with them",
        "rate_rec_crawler": "- Keep the budget, but count only the real search engine crawler: add the `crawler:verified` label from the ASN + User-Agent rule in Appendix A to the scope-down. Leave forged User-Agents to a per-IP limit\n",
        "no_ip_counted": "- {rules} would limit per IP, but it's in Count\n",
        "rule_na_global": "**Rule**: N/A (Web ACL global configuration)",
        "traversal_note": "- The path branches use `STARTS_WITH` without `NORMALIZE_PATH`. `/prefix/../admin` also starts with the prefix; if CloudFront or the origin resolves `..`, the request reaches a path the rule never meant to allow\n",
        "traversal_rec": "- Add `NORMALIZE_PATH` (after `URL_DECODE`) to the path conditions of this Allow rule\n",
        "rec_other_crawlers": "- AI crawlers and agents don't affect search ranking, so they need no Allow: remove their names from this rule\n",
        "after_last_allow": "- These rules run after the last Allow rule: {others}. The default action is Block, so every request that reaches them ends in Block anyway. They can't change the outcome, only the response code",
        "rec_after_last_allow": "- Move rules that should act on allowed traffic ahead of the Allow rules, or remove the ones that have no purpose here",
        "exempt_crawler": "- For search engine crawlers, exempt the `crawler:verified` label from the ASN + User-Agent rule in Appendix A instead of User-Agent strings\n",
        "hosting_scope_state": ", rule group scope-down `{scope}`",
        "hosting_scope": "- The rule group's scope-down is `{scope}`. Only requests that match it enter the rule group, so the bypass covers cloud-hosted requests that match the scope-down\n",
        "hosting_scope_widen": "- Before removing or widening that scope-down, change this override. Otherwise the bypass widens with it\n",
        "allow_override": "`{rule}` overridden to Allow",
        "levels": lambda lv: {1: "{}", 2: "{} and {}"}.get(len(lv), "{}, {}, and {}").format(*lv),
        "challenge_rules_any": "the Challenge rules",
        "exempt_inactive": "- Neither Challenge rule acts today (`ChallengeAllDuringEvent` is in Count and `ChallengeDDoSRequests` is off), so this matters once Challenge is turned back on\n",
        "crawler_inactive": "- `ChallengeAllDuringEvent` is in Count, so the rule group doesn't challenge crawlers across the board today. Add this rule before turning it back on\n",
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
        "bot_control_not_last": "- Bot Control {rules}排在自己会拦截或 Challenge 请求的规则 {others} 前面。Bot Control 按检查的请求数收费，这些规则拦下的请求已经先计过费了。这一条只影响费用，不影响安全",
        "label_no_producer": "- {rules}匹配标签 `{label}`，但这个 Web ACL 里没有任何规则会加这个标签。这个条件永远不会成立",
        "unreachable": "- {rules}永远收不到请求：它能匹配的请求，在前面已经被 {others}（{actions}）结束了",
        "rec_label_before_producer": "- 把产生标签的规则调到匹配该标签的规则前面",
        "rec_blocklist_after_allow": "- 把 IP 黑名单调到所有 Allow 规则前面",
        "rec_inspection_after_allow": "- 把内容检测规则组调到 Allow 规则前面，放行之前先检查。先用 Count 观察误报，再切回默认动作",
        "rec_bot_control_not_last": "- 把 Bot Control 放到这些会拦截或 Challenge 的规则后面",
        "rec_label_no_producer": "- 核对标签名。如果产生这个标签的规则已经删掉，这个条件也要删掉或改写",
        "rec_unreachable": "- 想清楚这部分流量该由哪条规则处理：收窄前面那条规则的条件，或者删掉后面这条",
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
        "rec_amr": "- Anti-DDoS：在 ACL 最前面加 `AWSManagedRulesAntiDDoSRuleSet`，放在只按 IP set 放行的白名单和爬虫标记规则（附录 A）之后，不要用 scope-down 把它限定在少数路径上，它要看到全部流量才能建立基线（附录 B 的双实例拆分例外）。API 和机器调用的路径用豁免正则排除在 Challenge 之外",
        "rec_iprep": "- IP 信誉：`AWSManagedRulesAmazonIpReputationList` 放在 Anti-DDoS 之后、限速和自定义规则之前",
        "rec_anon": "- 匿名 IP：`AWSManagedRulesAnonymousIpList` 放在 IP 信誉列表旁边，先用 Count。用 scope-down 限定在调用方是最终用户的 host 或路径上：`HostingProviderIPList` 会拦非 AWS 的云主机 IP，可能误伤部署在其他云上的合作方",
        "rec_bot": "- Bot Control：放在 ACL 最后，固定到最新的静态版本，用 scope-down 限定在浏览器访问的 host 或路径上",
        "placement_block": "- 这个 ACL 默认 Block：规则组要放在 Allow 规则前面，否则检查不到被放行的流量。用 scope-down 限定在需要检查的路径上，先用 Count 观察",
        "placement_allow": "- 放在 IP 信誉和限速规则之后",
        "example_ua": "匹配的 User-Agent",
        "example_header": "匹配的请求头",
        "example_cookie": "匹配的 cookie",
        "example_query": "匹配的查询参数",
        "example_other": "匹配的值",
        "sum_managed": "- {g} 个托管规则组里共有 {k} 条规则处于 Count，只打标签不拦截{whole}",
        "sum_whole": "；{names} 整组什么都不拦",
        "sum_order": "- 发现 {n} 处会影响检查或拦截的顺序问题：{kinds}",
        "kind_label_before_producer": "标签在产生之前就被使用",
        "kind_label_no_producer": "用了没有规则产生的标签",
        "kind_blocklist_after_allow": "黑名单排在 Allow 后面",
        "kind_inspection_after_allow": "内容检测排在 Allow 后面",
        "kind_unreachable": "{c} 条规则永远收不到请求",
        "kind_after_last_allow": "{c} 条规则改变不了结果",
        "kind_bot_control_not_last": "Bot Control 在拦截规则之前就计费",
        "sum_exempt": "- {n} 条规则会跳过带特定值的请求，这些值任何客户端都能发（{fields}）",
        "sum_dead": "- {r} 条规则里有 {n} 个模式永远匹配不上，这些条件没有起到本来的作用",
        "sum_noop": "- {n} 个 override 设成了规则本来的动作，什么也没改",
        "sum_rate_challenge": "- {n} 条限速的动作是 Challenge 或 CAPTCHA，客户端拿到有效 token 后就不再受限",
        "sum_rate_shared": "- {n} 条限速让所有匹配的客户端共用一个计数，伪造同样的值就能把额度用完",
        "sum_unused": "- {n} 条规则加的标签没有任何规则使用",
        "sum_uri": "- {n} 个 URI 路径条件按现在的写法永远匹配不上",
        "or_join": " 或",
        "f_header": "请求头 `{name}`",
        "f_cookie": "cookie `{name}`",
        "f_cookies": "cookie",
        "f_query_arg": "查询参数 `{name}`",
        "f_query": "查询串",
        "f_body": "请求体",
        "or_note": "- 这些条件和 {safe} 是 OR 关系，命中任意一个分支就放行，{safe} 条件管不住可伪造的分支\n",
        "or_rec": "- 这条 Allow 规则只保留 {safe} 条件，删掉可伪造的分支\n",
        "path_note": "- 限定在 {paths} 上的分支，同样能用伪造的请求在这些路径上放行\n",
        "path_open": "- 限定在 {paths} 上的分支，访问这些路径的请求不用伪造任何东西就会被放行\n",
        "skipped": "，包括所有可能拦下这个请求的规则（{rules}）",
        "skipped_more": "共 {total} 条：{rules} 等",
        "skipped_default": "。这个 ACL 默认 Block，这条规则也是进来的入口：带上这个值的请求就能进来",
        "rec_count_label": "- 需要识别这部分流量的话，用 Count+Label 规则（如 `custom:native-app` 或 `custom:probe`）代替 Allow，这些流量不需要绕过 WAF\n",
        "rec_unforgeable": "- 如果是给内部探针、监控或测试人员用的，改用不可伪造的条件，比如 IP set\n",
        "rec_default_block": "- 这个 ACL 默认 Block，改成 Count+Label 的话这些请求就进不来了。改按来源 IP 放行：用 IP set，测试人员走办公网出口或 VPN。WAF token 不能当访问凭据，任何浏览器都拿得到\n",
        "rec_crawler": "- 搜索引擎爬虫用附录 A 的 ASN + User-Agent 标记规则识别，需要时排除 `crawler:verified` 标签，不要按 User-Agent 放行\n",
        "exemption": "- `{rule}`（priority {p}）：{field} {match} `{value}` 的请求会跳过{what}",
        "what_managed_rule_group": "整个规则组",
        "what_rate_based": "限速",
        "what_custom": "这条规则",
        "case_dead": "- `{rule}`（priority {p}）：做了 {transform} 之后，{field} 里不可能出现 {dead}{whole}{neg}",
        "case_whole": "，这个条件永远不会命中",
        "case_neg": "。它在 NOT 里面，所以这项排除永远不起作用",
        "case_neg_part": "。它在 NOT 里面，所以这些请求不会被排除",
        "case_rec": "- 按转换后的大小写来写这些模式，比如 LOWERCASE 之后写 `adsbot-google`",
        "case_rec_allow": "- `{rule}` 是可伪造的 Allow，不要在那里修这个模式，改对了放行范围反而更大。删掉可伪造的分支，这个问题也就没了",
        "case_why": "- WAF 先做文本转换再匹配，做完 LOWERCASE 之后输入里就没有大写字母了（UPPERCASE 反过来）",
        "crawler_dead_ua": "- `{rule}`（priority {p}）：{dead} 匹配不上 {family} 官方公布的任何一个 User-Agent{whole}{neg}",
        "crawler_dead_robots": "- `{rule}`（priority {p}）：{dead} 只是 robots.txt 里用的名字，{family} 说明它不会出现在 User-Agent 里，这个分支不起作用{whole}{neg}",
        "dead_rec_ua": "- 这些是按 User-Agent 识别爬虫的条件，模式写对了，任何客户端照样能发。改用附录 A 的 ASN + User-Agent 规则打的 `crawler:verified` 标签来识别爬虫。暂时还要保留 User-Agent 条件的话，按爬虫实际发送的写法来写：LOWERCASE 之后用小写，写 `bingbot` 而不是 `bingbot.html`",
        "exempt_count": "（这条规则现在是 Count，切到它原本要的动作后才会起作用）",
        "exempt_label": "（这是一条 Count+Label 规则：这些请求拿不到它的标签，后面按这个标签处理的规则也就跳过了它们）",
        "exempt_default_block": "（这个 ACL 默认 Block，后面也没有规则会放行，所以现在跳过它不影响结果）",
        "exempt_browser": "（预取请求完成不了 Challenge，这种排除通常是有意的）",
        "exempt_browser_rec": "- 浏览器预取的排除，只限定在会被预取的页面的 GET 请求上，并保留一条不排除它们的限速\n",
        "still_blocking": "；只剩 {names} 还会拦，而且要看当前运行的版本里有没有这条规则",
        "still_blocking_now": "；只剩 {names} 还会拦",
        "all_counted": "；组里所有规则都是 Count，整个规则组只打标签",
        "noop": "- `{rule}`（priority {p}，{group}）：{names}，都是这些规则本来的默认动作",
        "rate_challenge": "- `{rule}`（priority {p}）：超过 {limit} 次后执行 {action}。拿到有效 token 的客户端，每次通过后的 {immunity} 秒内发多快都不会被限",
        "rate_shared": "- `{rule}`（priority {p}）：按 `{key}` 计数，{window} 秒 {limit} 次。所有匹配的客户端算在同一个计数里，一个客户端就能让共用这个值的所有请求一起超限",
        "unused_label": "- `{rule}`（priority {p}，{action}）：加了 {labels}，但没有规则匹配它",
        "rate_rec_shared": "- 把 IP 加进聚合键；或者确认让共用这个值的所有请求共享一份额度，就是你想要的效果\n",
        "rate_shared_crawler": "- `{rule}`（priority {p}）：带这个 User-Agent 的所有请求共用一份额度，{window} 秒 {limit} 次（`{key}`），搜索引擎爬虫也会带这个 User-Agent。这个 User-Agent 谁都能发，伪造的请求会把额度用完，真正的爬虫也跟着被拦",
        "rate_rec_crawler": "- 额度可以保留，但只算真正的搜索引擎爬虫：在 scope-down 里加上附录 A 的 ASN + User-Agent 规则打的 `crawler:verified` 标签。伪造 User-Agent 的请求交给按 IP 的限速\n",
        "no_ip_counted": "- {rules} 本来会按 IP 限速，但它是 Count\n",
        "rule_na_global": "**Rule**: N/A (Web ACL 全局配置)",
        "traversal_note": "- 这些路径分支用的是 `STARTS_WITH`，没有 `NORMALIZE_PATH`。`/prefix/../admin` 也以这个前缀开头，如果 CloudFront 或源站会解析 `..`，请求就会到达规则本来没打算放行的路径\n",
        "traversal_rec": "- 给这条 Allow 规则的路径条件加上 `NORMALIZE_PATH`（放在 `URL_DECODE` 之后）\n",
        "rec_other_crawlers": "- AI 爬虫和 agent 不影响搜索排名，不需要放行，直接从这条规则里删掉它们的名字\n",
        "after_last_allow": "- 这些规则排在最后一条 Allow 之后：{others}。默认动作是 Block，走到这里的请求最后都会被 Block，这些规则改变不了结果，最多改变响应码",
        "rec_after_last_allow": "- 需要作用于放行流量的规则，挪到 Allow 规则前面；在这里没有用处的规则可以删掉",
        "exempt_crawler": "- 搜索引擎爬虫改为排除附录 A 的 ASN + User-Agent 规则打上的 `crawler:verified` 标签，不要按 User-Agent 字符串排除\n",
        "hosting_scope_state": "，规则组的 scope-down 为 `{scope}`",
        "hosting_scope": "- 规则组的 scope-down 是 `{scope}`，只有匹配它的请求才会进入规则组。所以被放行的是匹配这个 scope-down 的云主机请求\n",
        "hosting_scope_widen": "- 要去掉或放宽这个 scope-down，先改掉这个 override，否则放行范围会跟着扩大\n",
        "allow_override": "`{rule}` 被覆盖为 Allow",
        "levels": lambda lv: "、".join({"low": "低", "medium": "中", "high": "高"}[x] for x in lv),
        "challenge_rules_any": "Challenge 规则",
        "exempt_inactive": "- 目前两条 Challenge 规则都没有生效（`ChallengeAllDuringEvent` 是 Count，`ChallengeDDoSRequests` 也没开），重新打开 Challenge 后这个问题才会起作用\n",
        "crawler_inactive": "- `ChallengeAllDuringEvent` 现在是 Count，规则组目前不会对爬虫一律 Challenge。重新打开它之前先加上这条规则\n",
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


def _amr_state(summary: dict) -> dict | None:
    """Which Anti-DDoS Challenge rules act today. ChallengeDDoSRequests only
    runs when ChallengeAllDuringEvent is overridden to Count, and
    usage_of_challenge_action DISABLED turns both off."""
    amr = next((r for r in summary.get("rules", [])
                if AMR_GROUP == (r.get("managed") or {}).get("group_name")), None)
    if not amr:
        return None
    mg = amr["managed"]
    over = {o.get("rule_name"): o.get("action") for o in mg.get("overrides", [])}
    enabled = (mg.get("config") or {}).get("usage_of_challenge_action") != "DISABLED"
    cade = enabled and "ChallengeAllDuringEvent" not in over
    cdr = (enabled and over.get("ChallengeAllDuringEvent") == "count"
           and "ChallengeDDoSRequests" not in over)
    return {"rule": amr, "enabled": enabled, "cade": cade, "cdr": cdr}


def _token_challenge(rules: list) -> list:
    """TARGETED Bot Control with TGT_TokenAbsent overridden to Challenge or
    CAPTCHA: every token-less request in its scope gets challenged, which is
    an always-on Challenge for that scope."""
    out = []
    for r in rules:
        mg = r.get("managed") or {}
        if (mg.get("group_name") == BOT_GROUP
                and (mg.get("config") or {}).get("inspection_level") == "TARGETED"
                and any(o["rule_name"] == "TGT_TokenAbsent" and o["action"] in ("challenge", "captcha")
                        for o in mg.get("overrides", []))):
            out.append(r)
    return out


def _rule_line(items: list) -> str:
    """The rule reference line: `**Rule**:` for one rule, `**Rules**:` for several."""
    return ("**Rule**: " if len(items) == 1 else "**Rules**: ") + _refs(items)


def _ticks(items: list, lang: str = "en") -> str:
    return ("、" if lang == "zh" else ", ").join(f"`{i['name']}`" for i in items)


NOT_APPLICABLE = "NOT_APPLICABLE"
AMBIGUOUS = "AMBIGUOUS"


# ── Helpers ────────────────────────────────────────────────────────────────



def _short_arns(text: str) -> str:
    """IP and regex set ARNs shortened to their names for Current state lines."""
    return re.sub(r"arn:aws:wafv2:[^'\s]*?/(?:ipset|regexpatternset)/([^/'\s]+)/[^'\s]+", r"\1", text)


def _field_label(field: str, L: dict) -> str:
    """A leaf's field in plain words: `cookies[scope=ALL, included=a]` → the `a` cookie."""
    base, _, rest = field.partition(":")
    if base == "single_header":
        return "User-Agent" if rest == "user-agent" else L["f_header"].format(name=rest)
    if base == "single_query_argument":
        return L["f_query_arg"].format(name=rest)
    m = re.match(r"cookies\[.*?included=([^,\]]+)", field)
    if m:
        return L["f_cookie"].format(name=m.group(1))
    return {"query_string": L["f_query"], "body": L["f_body"]}.get(base) or (
        L["f_cookies"] if base.startswith("cookies") else field)


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
    default_block = summary.get("web_acl", {}).get("default_action") == "block"
    sep = "、" if lang == "zh" else ", "
    # Group by forgeable_conditions content
    groups = defaultdict(list)
    for a in candidates:
        key = tuple(sorted(a.get("forgeable_conditions", [])))
        groups[key].append(a)

    results = []
    for key, group in groups.items():
        names = [a["name"] for a in group]
        rule_names = " / ".join(names)
        rule_line = _rule_line(group)

        fc = group[0]["forgeable_conditions"]
        forgeable_fields = sep.join(dict.fromkeys(_field_label(c, L) for c in fc))
        is_are = "is" if len(set(forgeable_fields.split(sep))) == 1 else "are"
        ua = any("user-agent" in c for c in fc)
        kinds = []
        for c in fc:
            k = ("example_ua" if "user-agent" in c else "example_cookie" if c.startswith("cookie")
                 else "example_query" if "query" in c else "example_header" if "header" in c else "example_other")
            if k not in kinds:
                kinds.append(k)
        forgeable_example = L["or_join"].join(L[k] for k in kinds)

        # The later rules a matching request skips
        first = min(a["priority"] for a in group)
        later = [r for r in summary.get("rules", []) if r["priority"] > first and r["action"] != "count"
                 and r["name"] not in names and not (r["type"] == "custom" and r["action"] == "allow")]
        shown = sep.join(f"`{r['name']}`" for r in later[:5])
        if len(later) > 5:
            shown = L["skipped_more"].format(rules=shown, k=len(later) - 5, total=len(later))
        skipped = L["skipped"].format(rules=shown) if later else ""
        if default_block:
            skipped += L["skipped_default"]

        safe = ", ".join(group[0].get("safe_conditions", []))
        notes = L["or_note"].format(safe=safe) if safe else ""
        for forged, key in ((True, "path_note"), (False, "path_open")):
            paths = [p for a in group for b in a.get("path_branches", []) if b["forged"] == forged for p in b["paths"]]
            if paths:
                notes += L[key].format(paths=sep.join(f"`{p}`" for p in dict.fromkeys(paths)))
        recs = L["or_rec"].format(safe=safe) if safe else ""
        crawler = ua and re.search(r"bot|spider|crawl|slurp", group[0]["statement_summary"], re.I)
        if crawler:
            recs += L["rec_crawler"]
            if re.search(r"gpt|claude|openai|anthropic|meta-|facebook|bytespider|perplexity|chatgpt",
                         group[0]["statement_summary"], re.I):
                recs += L["rec_other_crawlers"]
        if any(a.get("prefix_unnormalized") for a in group):
            notes += L["traversal_note"]
            recs += L["traversal_rec"]
        if default_block:
            recs += L["rec_default_block"]
        else:  # Count+Label fits native apps and probes, not crawlers
            recs += ("" if crawler else L["rec_count_label"]) + L["rec_unforgeable"]

        md = T["forgeable_allow"].format(
            n="{n}", rule_names=rule_names, rule_line=rule_line,
            stmt_summary=_short_arns(group[0]["statement_summary"]),
            forgeable_fields=forgeable_fields, is_are=is_are,
            forgeable_example=forgeable_example, skipped=skipped, notes=notes, recs=recs)
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
    rule_line = _rule_line([{"name": s["rule"], "priority": s["priority"]} for s in narrow])
    md = T["scope_down_too_narrow"].format(n="{n}", rule_line=rule_line)
    return [(md, {"severity": "Medium", "title_key": "scope_down_too_narrow",
                  "rules": [s["rule"] for s in narrow], "sections": [2]})]


def _gen_challenge_on_post_api(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("challenge_on_post_api", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    rules = check.get("rules", [])
    rule_line = _rule_line(rules)
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
            recs.append("- 评估是否需要添加 CRS；如果添加，务必将 `SizeRestrictions_BODY` 覆盖为 Count，避免对大 payload 的 API 端点产生误报（实现步骤见附录 F）")
        else:
            details.append("CRS provides OWASP Top 10 protection (SQLi, XSS, etc.), the baseline protection layer for most web applications")
            recs.append("- Evaluate whether to add CRS; if adding, override `SizeRestrictions_BODY` to Count to avoid false positives on large-payload API endpoints (see Appendix F)")
    if "KnownBadInputs" in missing:
        if lang == "zh":
            details.append("KnownBadInputsRuleSet 防护 Log4Shell（CVE-2021-44228）、Java 反序列化漏洞等已知恶意输入模式，WCU 消耗低、误报率低")
            recs.append("- 添加 AWSManagedRulesKnownBadInputsRuleSet（WCU 消耗低，建议优先添加）")
        else:
            details.append("KnownBadInputsRuleSet protects against Log4Shell (CVE-2021-44228), Java deserialization exploits, and other known malicious input patterns, with low WCU cost and few false positives")
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
        n="{n}", rule_names=rule_names, rule_line=_rule_line(rules))
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
    state = _amr_state(summary)
    if not regex_flags or (state and not state["enabled"]):
        return NOT_APPLICABLE  # the exempt regex only matters while Challenge is in use
    L = LINES[lang]
    active = [n for n, on in (("ChallengeAllDuringEvent", state and state["cade"]),
                              ("ChallengeDDoSRequests", state and state["cdr"])) if on]
    severity = "Medium" if active else "Low"
    challenge_rules = " / ".join(f"`{n}`" for n in active) or L["challenge_rules_any"]
    state_note = "" if active else L["exempt_inactive"]
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
            n="{n}", severity=severity, rule_name=rf["rule"], priority=rf["priority"],
            regex=rf["full_regex"], unanchored_list=unanchored_list,
            examples=examples, anchored_suggestion=anchored,
            challenge_rules=challenge_rules, state_note=state_note)
        results.append((md, {"severity": severity, "title_key": "unanchored_exempt_regex",
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
    state = _amr_state(summary)
    # Crawlers get challenged by the blanket ChallengeAllDuringEvent; while it's
    # off, the labeling rule is preparation for turning it back on
    severity = "Medium" if state and state["cade"] else "Low"
    md = T["missing_crawler_labeling"].format(
        n="{n}", severity=severity,
        state_note="" if severity == "Medium" else LINES[lang]["crawler_inactive"])
    return [(md, {"severity": severity, "title_key": "missing_crawler_labeling",
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
    md = T["duplicate_rules"].format(n="{n}", count=len(groups), rule_line=_rule_line(rules),
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
            n="{n}", rule_line=_rule_line(others),
            groups=", ".join(f"`{u['group']}`" for u in others), sqli_note=sqli_note)
        results.append((md, {"severity": "Low", "title_key": "managed_unpinned",
                             "rules": [u["name"] for u in others], "sections": [12]}))
    return results if results else NOT_APPLICABLE


def _gen_missing_always_on_challenge(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    has_amr = any("AntiDDoS" in r.get("managed", {}).get("group_name", "") for r in rules)
    if not has_amr:
        # Without AMR the DDoS objective is unknown; an internet-facing ACL goes to the LLM
        return AMBIGUOUS if summary.get("web_acl", {}).get("default_action") == "allow" else NOT_APPLICABLE
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
    if _token_challenge(rules):
        return AMBIGUOUS  # covers only Bot Control's scope; the LLM judges whether that's enough
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
        others = i.get("producers") or i.get("allows") or i.get("later") or i.get("stoppers") or []
        key = (i["kind"], i.get("label", ""), i.get("group", ""), tuple(o["name"] for o in others))
        merged.setdefault(key, {"issue": i, "others": others, "subjects": []})["subjects"].append(i["rule"])
    fmt = "`{}`（priority {}）" if lang == "zh" else "`{}` (priority {})"
    sep = "、" if lang == "zh" else ", "
    problems, kinds = [], []
    for (kind, label, group, _), m in merged.items():
        problems.append(L[kind].format(
            rules=sep.join(fmt.format(r["name"], r["priority"]) for r in m["subjects"]),
            label=label, group=group, others=_ticks(m["others"], lang),
            actions="/".join(a.capitalize() for a in m["issue"].get("actions", []))))
        if kind not in kinds:
            kinds.append(kind)
    recs = "\n".join(L["rec_" + k] for k in kinds)
    counts = {k: sum(1 for i in check["issues"] if i["kind"] == k) for k in kinds}
    n_problems = len(problems)
    problems.insert(0, L["sum_order"].format(
        n=n_problems, kinds=sep.join(L["kind_" + k].format(c=counts[k]) for k in kinds)))
    # Medium when it changes what gets inspected or blocked: a protection that
    # never runs because an Allow ends the request first. Cost and dead code are Low.
    medium = any(i["kind"] in ("label_before_producer", "label_no_producer", "blocklist_after_allow",
                               "inspection_after_allow")
                 or (i["kind"] == "unreachable" and "allow" in i["actions"] and i.get("rule_action") != "count")
                 for i in check["issues"])
    severity = "Medium" if medium else "Low"
    md = T["order_issues"].format(
        n="{n}", severity=severity, summary=L["order_title"].format(count=n_problems),
        rule_line=_rule_line(check["rules"]), problems="\n".join(problems), recs=recs)
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
        n="{n}", severity=severity, rule_line=_rule_line(rules), rule_names=_ticks(rules, lang),
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
    details.insert(0, L["sum_uri"].format(n=len(details)))
    kinds = {pb["kind"] for r in check["rules"] for pb in r["problems"]}
    recs = [L["rec_" + k] for k in ("literal_wildcard", "query_in_path") if k in kinds]
    md = T["uri_path_pitfalls"].format(
        n="{n}", rule_line=_rule_line(check["rules"]), details="\n".join(details),
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
        n="{n}", rule_line=_rule_line(check["rules"]), details="\n".join(details))
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
    L = LINES[lang]
    trav = any(r.get("prefix_unnormalized") for r in rules)
    md = T["path_only_allow"].format(
        n="{n}", severity=severity, rule_line=_rule_line(rules), rule_names=_ticks(rules, lang),
        acl_note=(L["default_block_note"] if default_block else "") + (L["traversal_note"] if trav else ""),
        trav_rec=L["traversal_rec"] if trav else "")
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
                + ("" if o.get("still_blocking") is None else L["all_counted"] if not o["still_blocking"]
                   else L["still_blocking" if o.get("group_versioned") else "still_blocking_now"].format(
                       names=", ".join(f"`{x}`" for x in o["still_blocking"])))
                for o in check.get("overrides", [])]
    sep = "、" if lang == "zh" else ", "
    whole = [g["group"] for g in check.get("groups", [])] + [
        o["group"] for o in check.get("overrides", []) if o.get("still_blocking") == []]
    k = sum(len(o["overridden"]) for o in check.get("overrides", []))
    details.insert(0, L["sum_managed"].format(
        k=k, g=len(check["rules"]),
        whole=L["sum_whole"].format(names=sep.join(f"`{x}`" for x in whole)) if whole else ""))
    md = T["managed_count"].format(
        n="{n}", rule_line=_rule_line(check["rules"]), details="\n".join(details))
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


def _gen_forgeable_exemptions(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("forgeable_exemptions", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    L = LINES[lang]
    notes = {"count": L["exempt_count"], "default_block": L["exempt_default_block"],
             "browser_signal": L["exempt_browser"], "label": L["exempt_label"], "bypass": ""}
    details = []
    for r in check["rules"]:
        for e in r["exemptions"]:
            v = str(e["value"])
            details.append(L["exemption"].format(
                rule=r["name"], p=r["priority"], field=_field_label(e["field"], L), match=e["match"] or "",
                value=v[:77] + "..." if len(v) > 80 else v, what=L["what_" + r["type"]])
                + notes[r.get("impact", "bypass")])
    sep = "、" if lang == "zh" else ", "
    details.insert(0, L["sum_exempt"].format(n=len(check["rules"]), fields=sep.join(dict.fromkeys(
        _field_label(e["field"], L) for r in check["rules"] for e in r["exemptions"]))))
    ua = any("user-agent" in e["field"] for r in check["rules"] for e in r["exemptions"])
    recs = (L["exempt_crawler"] if ua else "") + (
        L["exempt_browser_rec"] if any(r.get("impact") == "browser_signal" for r in check["rules"]) else "")
    # Medium only where skipping the protection lets an attack through today
    severity = "Medium" if any(r.get("impact", "bypass") in ("bypass", "label") for r in check["rules"]) else "Low"
    md = T["forgeable_exemptions"].format(n="{n}", severity=severity, rule_line=_rule_line(check["rules"]),
                                          details="\n".join(details), crawler_rec=recs)
    return [(md, {"severity": severity, "title_key": "forgeable_exemptions",
                  "rules": [r["name"] for r in check["rules"]], "sections": [2]})]


def _gen_dead_patterns(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("dead_patterns", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    L = LINES[lang]
    sep = "、" if lang == "zh" else ", "
    details = []
    for f in check["rules"]:
        neg = (L["case_neg"] if f["whole"] else L["case_neg_part"]) if f["negated"] else ""
        whole = L["case_whole"] if f["whole"] else ""
        if f["dead"]:
            details.append(L["case_dead"].format(rule=f["name"], p=f["priority"], transform=f["transform"],
                                                 field=_field_label(f["field"], L), dead=sep.join(f"`{d}`" for d in f["dead"]),
                                                 whole=whole, neg=neg))
        for c in f["crawler"]:
            # A robots.txt-only name is redundant, not harmful: those requests carry another UA
            details.append(L["crawler_dead_" + c["kind"]].format(rule=f["name"], p=f["priority"],
                                                                 dead=f"`{c['pattern']}`", family=c["family"].capitalize(),
                                                                 whole=whole, neg="" if c["kind"] == "robots" else neg))
    rules = list({f["name"]: f for f in check["rules"]}.values())
    details.insert(0, L["sum_dead"].format(
        n=sum(len(f["dead"]) + len(f["crawler"]) for f in check["rules"]), r=len(rules)))
    if any(f["dead"] for f in check["rules"]):
        details.append(L["case_why"])
    forged = {a["name"] for a in flags.get("allow_rules", []) if a.get("all_forgeable")}
    recs = [L["case_rec_allow"].format(rule=n) for n in dict.fromkeys(f["name"] for f in check["rules"])
            if n in forged]
    rest = [f for f in check["rules"] if f["name"] not in forged]
    # A crawler condition on the User-Agent stays forgeable even when written right
    if any(f["field"] == "single_header:user-agent" for f in rest):
        recs.append(L["dead_rec_ua"])
    if any(f["field"] != "single_header:user-agent" for f in rest):
        recs.append(L["case_rec"])
    md = T["dead_patterns"].format(n="{n}", rule_line=_rule_line(rules), details="\n".join(details),
                                   recs="\n".join(recs))
    return [(md, {"severity": "Low", "title_key": "dead_patterns",
                  "rules": [f["name"] for f in rules], "sections": [19]})]


def _gen_noop_overrides(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("noop_overrides", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    L = LINES[lang]
    names = {"block": "Block", "count": "Count", "challenge": "Challenge", "captcha": "CAPTCHA"}
    details = [L["noop"].format(rule=f["name"], p=f["priority"], group=f["group"],
                                names=", ".join(f"`{x}` → {names[a]}" for x, a in zip(f["overrides"], f["actions"])))
               for f in check["rules"]]
    details.insert(0, L["sum_noop"].format(n=sum(len(f["overrides"]) for f in check["rules"])))
    md = T["noop_overrides"].format(n="{n}", rule_line=_rule_line(check["rules"]), details="\n".join(details))
    return [(md, {"severity": "Awareness", "title_key": "noop_overrides",
                  "rules": [f["name"] for f in check["rules"]], "sections": [20]})]


def _gen_rate_limits(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("rate_limits", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    L = LINES[lang]
    names = {"challenge": "Challenge", "captcha": "CAPTCHA"}
    out = []
    if check.get("no_ip_limit"):
        counted = check.get("counted_ip", [])
        md = T["no_ip_rate_limit"].format(
            n="{n}", rule_line=_rule_line(counted) if counted else LINES[lang]["rule_na_global"],
            counted=L["no_ip_counted"].format(rules=_ticks(counted, lang)) if counted else "")
        out.append((md, {"severity": "Medium", "title_key": "no_ip_rate_limit",
                         "rules": [f["name"] for f in counted], "sections": [6]}))
    if check["challenge"]:
        details = [L["rate_challenge"].format(rule=f["name"], p=f["priority"], action=names[f["action"]],
                                              limit=f["limit"], immunity=f["immunity"]) for f in check["challenge"]]
        details.insert(0, L["sum_rate_challenge"].format(n=len(check["challenge"])))
        md = T["rate_challenge"].format(n="{n}", rule_line=_rule_line(check["challenge"]), details="\n".join(details))
        out.append((md, {"severity": "Low", "title_key": "rate_challenge",
                         "rules": [f["name"] for f in check["challenge"]], "sections": [6]}))
    if check["shared"]:
        details = [L["rate_shared_crawler" if f.get("crawler_budget") else "rate_shared"].format(
            rule=f["name"], p=f["priority"], key=f["key"], limit=f["limit"], window=f["window"])
            for f in check["shared"]]
        recs = (L["rate_rec_crawler"] if any(f.get("crawler_budget") for f in check["shared"]) else "") + (
            L["rate_rec_shared"] if any(not f.get("crawler_budget") for f in check["shared"]) else "")
        details.insert(0, L["sum_rate_shared"].format(n=len(check["shared"])))
        md = T["rate_shared"].format(n="{n}", rule_line=_rule_line(check["shared"]),
                                     details="\n".join(details), recs=recs)
        out.append((md, {"severity": "Low", "title_key": "rate_shared",
                         "rules": [f["name"] for f in check["shared"]], "sections": [6]}))
    return out


def _gen_unused_labels(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("unused_labels", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    L = LINES[lang]
    details = [L["unused_label"].format(rule=f["name"], p=f["priority"], action=f["action"].capitalize(),
                                        labels=", ".join(f"`{x}`" for x in f["labels"])) for f in check["rules"]]
    details.insert(0, L["sum_unused"].format(n=len(check["rules"])))
    md = T["unused_labels"].format(n="{n}", rule_line=_rule_line(check["rules"]), details="\n".join(details))
    return [(md, {"severity": "Awareness", "title_key": "unused_labels",
                  "rules": [f["name"] for f in check["rules"]], "sections": [17]})]


def _gen_security_automations(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("security_automations", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    md = T["security_automations"].format(n="{n}", rule_line=_rule_line(check["rules"]))
    return [(md, {"severity": "Awareness", "title_key": "security_automations",
                  "rules": [f["name"] for f in check["rules"]], "sections": [7]})]


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
    (_gen_forgeable_exemptions, [2], True),
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
    (_gen_default_action_redundancy, [15], True),
    (_gen_missing_always_on_challenge, [16], True),
    (_gen_count_without_labels, [17], True),  # Covers 17a only; 17 is always-LLM
    (_gen_order_issues, [18], True),
    (_gen_recommended_protections, [3, 5, 7], False),
    (_gen_uri_fragment_fallback, [1, 19], True),
    (_gen_path_only_allow, [1], True),
    (_gen_uri_path_pitfalls, [19], True),
    (_gen_path_block_decoding, [19], True),
    (_gen_dead_patterns, [19], True),
    (_gen_managed_count, [20], True),
    (_gen_noop_overrides, [20], True),
    (_gen_rate_limits, [6], False),  # Section 6 needs the LLM when rate rules exist
    (_gen_unused_labels, [17], True),
    (_gen_security_automations, [7], False),
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

    summary_path = work_path(output_dir, "waf-summary.json")
    prechecks_path = work_path(output_dir, "pre-checks.json")

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
        if s in ALWAYS_LLM_SECTIONS or s in APPENDIX_ONLY_SECTIONS or s in RETIRED_SECTIONS:
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
    # Generators only cover part of these sections; the LLM reviews them whenever
    # the Web ACL has the rules they're about
    rules_ = summary.get("rules", [])
    relevant = {
        4: any(r["action"] in ("challenge", "captcha") or any(
            o.get("action") in ("challenge", "captcha") for o in (r.get("managed") or {}).get("overrides", []))
            for r in rules_),
        6: any(r["type"] == "rate_based" for r in rules_),
        7: any((r.get("managed") or {}).get("group_name") in IP_REPUTATION_GROUPS for r in rules_),
    }
    llm_sections += [sec for sec, yes in relevant.items() if yes]
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
            for r in rules) or bool(_token_challenge(rules)),
        "has_crawler_labeling_rule": any(
            any(lbl.startswith(p) for p in CRAWLER_LABEL_PATTERNS)
            for r in rules for lbl in r.get("rule_labels", [])),
        "payment_indicators": _payment_indicators(summary),
    }

    next_issue_number = len(all_findings) + 1

    # Write scripted-findings.md
    findings_path = work_path(output_dir, "scripted-findings.md")
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
    meta_path = work_path(output_dir, "findings-metadata.json")
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
