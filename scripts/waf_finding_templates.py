"""Finding templates for WAF review reports (English and Chinese)."""

# ── English Templates ──────────────────────────────────────────────────────

TEMPLATES_EN = {
"forgeable_allow": """## Issue {n} (Critical): {rule_names} is a forgeable Allow rule that bypasses all later protections

{rule_line}
**Current state**: {stmt_summary}, action Allow, no scope-down

**Problem**:
- {forgeable_fields} {is_are} fully forgeable. Any client that sends {forgeable_example} skips every later rule{skipped}
- The blast radius is global: every path is affected, with no host or URI restriction
{notes}
**Recommendation**:
{recs}
---
""",
"hosting_provider_allow": """## Issue {n} ({severity}): HostingProviderIPList overridden to Allow, so cloud-hosted traffic skips all later rules

**Rule**: {rule_name} (priority {priority})
**Current state**: `HostingProviderIPList` overridden to Allow{scope_state}

**Problem**:
- `HostingProviderIPList` default-Blocks cloud hosting and web hosting provider IPs. With the Allow override, a request from these IPs is allowed at once and skips every later rule
- Modern DDoS attacks heavily use cloud infrastructure (VPS, cloud functions, containers). The Allow override lets this attack traffic bypass IP reputation, Bot Control, rate limiting, and all other protections
- The correct approach is to override to Count (preserves labels for downstream rules), not Allow
{scope_note}
**Recommendation**:
- Change `HostingProviderIPList` override from Allow to Count
- Count doesn't block, it only adds labels, so enterprise users routed through cloud proxies are not affected

---
""",
"scope_down_too_narrow": """## Issue {n} (Medium): IP reputation / Anonymous IP rule groups have a scope-down that only inspects the homepage

{rule_line}
**Current state**: scope-down is `uri_path EXACTLY '/'`, only applies to homepage path

**Problem**:
- Both rule groups only inspect `GET /` requests. All other paths (`/api/*`, `/login`, `/signup`, etc.) are not covered by IP reputation checks
- Malicious IPs only need to target any non-homepage path to completely bypass both rule groups
- This renders IP reputation protection effectively useless, especially for API path attacks

**Recommendation**:
- Remove the scope-down from both rule groups to inspect all traffic
- If scope restriction is needed for performance or cost, at minimum cover all critical paths, not just the homepage

---
""",
"challenge_on_post_api": """## Issue {n} (Medium): Challenge rules target API/POST paths, which is effectively Block

{rule_line}
**Current state**: Challenge action applied to API paths and/or POST requests

**Problem**:
- Challenge can only be completed by browser GET requests (requires JavaScript execution and HTML response)
- API paths are typically accessed by native apps or JavaScript fetch/XHR, which cannot complete Challenge
- POST requests cannot complete Challenge: the client receives HTTP 202 but cannot resubmit the original POST
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
- Token Domain uses suffix matching, so `{apex}` automatically covers all subdomains at any depth
- Listing subdomains is redundant; it does not cause security issues but adds configuration maintenance cost

**Recommendation**:
- Keep only `{apex}`, remove all subdomain entries

---
""",
"no_logging": """## Issue {n} (Awareness): No WAF logging configuration detected

**Rule**: N/A (Web ACL global configuration)
**Current state**: WAF JSON export does not include logging configuration

**Problem**:
- WAF logging configuration is not included in the Web ACL JSON export. This finding does not mean logging is disabled, only that it cannot be verified from the export
- WAF logs are essential for security incident investigation, rule tuning, and false positive analysis

**Recommendation**:
- Verify that WAF logging is enabled (Amazon Data Firehose, S3, or CloudWatch Logs) via the AWS Console or CLI
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
- Enable WAF logging to CloudWatch Logs, S3, or Amazon Data Firehose
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
"count_without_labels": """## Issue {n} (Awareness): {rule_names} are Count rules without labels, metrics only

{rule_line}
**Current state**: Count action, no RuleLabels

**Problem**:
- Count rules without labels only produce CloudWatch metrics. Downstream rules cannot act on the match result
- If the intent is to take action based on these matches, the current configuration cannot achieve it

**Recommendation**:
- If these rules are for monitoring only, give them names that say so
- If the intent is to act on matches (Block, Challenge, etc.), either change the action or add labels for downstream rules to consume
- Don't switch one to Allow unless its conditions can't be forged, such as an IP set: an Allow on a User-Agent or header lets any client skip every later rule

---
""",
"challenge_all_during_event": """## Issue {n} ({severity}): ChallengeAllDuringEvent overridden to Count, so the blanket Challenge during DDoS events is off

**Rule**: {rule_name} (priority {priority})
**Current state**: `ChallengeAllDuringEvent` overridden to Count

**Problem**:
- `ChallengeAllDuringEvent` is AntiDDoS AMR's blanket soft mitigation. During a DDoS event it Challenges every challengeable request, suspicious or not, which filters attack tools that can't run JavaScript
- Overriding it to Count means this rule only produces metrics during DDoS events, with no mitigation action
{details}

**Recommendation**:
- **Best**: if architecture supports it, use separate Web ACLs for frontend (browser) and backend (API/native app) traffic. Frontend Web ACL enables ChallengeAllDuringEvent with default config; backend Web ACL disables Challenge and raises Block sensitivity
- **If frontend and API share the same domain**: deploy dual AMR instances in the same Web ACL, one for browser traffic (ChallengeAllDuringEvent enabled), one for API/native app traffic (Challenge disabled, Block sensitivity MEDIUM). See Appendix B for implementation steps
- Do NOT use the "single instance + all Count + custom label rules" pattern. It requires understanding 6+ AMR labels, disables AMR's internal coordination logic, and still requires answering which paths can Challenge

---
""",
"dead_exempt_regex": """## Issue {n} ({severity}): AntiDDoS AMR exempt regex branches anchored with `^/` never match, so those paths get challenged

**Rule**: {rule_name} (priority {priority})
**Current state**: Exempt regex `{regex}`

**Problem**:
- AWS WAF matches the exempt regex against the request's host followed by its normalized path, such as `www.example.com/api/orders`, so a branch that starts with `^/` never matches: {dead_list}
- GET requests to those paths aren't exempt, and {challenge_rules} challenges them during a DDoS event. API and native app clients can't solve a Challenge, so those requests fail. Only GET requests are challengeable
{state_note}
**Recommendation**:
- Anchor after the host: {suggestion}. `^[^/]+` stands for any host; name the host instead (`^api\\.example\\.com\\/`) to exempt one host only
- The path loses a trailing slash before the match, so `\\/api\\/` doesn't match `/api` itself; `\\/api(\\/|$)` does
- Check the result in WAF logs: a request the regex exempts has no `awswaf:managed:aws:anti-ddos:challengeable-request` label, and the label is added outside DDoS events too

---
""",
"unanchored_exempt_regex": """## Issue {n} ({severity}): AntiDDoS AMR exempt URI regex is unanchored, so crafted paths skip Challenge

**Rule**: {rule_name} (priority {priority})
**Current state**: Exempt regex `{regex}`, path branches have no anchor

**Problem**:
- AWS WAF matches the exempt regex against the request's host followed by its normalized path. These branches have no anchor, so they match anywhere in it: {unanchored_list}
- Attackers can craft paths containing these keywords to get past {challenge_rules}, e.g.: {examples}
- This allows attack requests to be exempted from Challenge during DDoS events
{state_note}
**Recommendation**:
- Anchor the branches after the host: {suggestion}. `^[^/]+` stands for any host; name the host instead (`^api\\.example\\.com\\/`) to exempt one host only. Don't anchor with `^/`: the string starts with the host, so such a branch never matches
- Check the real paths first. If the API sits under a prefix such as `/v1/`, include it (`^[^/]+\\/v1\\/query`), or the anchored branch stops matching
- Static asset suffix matching (e.g., `\\.(css|js|png)$`) is already anchored with `$` and needs no change

---
""",
"missing_crawler_labeling": """## Issue {n} ({severity}): Missing crawler labeling rule, so search engine crawlers may be challenged during DDoS events

**Rule**: N/A (missing rule)
**Current state**: No ASN + UA crawler labeling rule in the Web ACL

**Problem**:
- `ChallengeAllDuringEvent` will Challenge all challengeable requests during DDoS events, including search engine crawlers (Googlebot, Bingbot, etc.)
- Real-world cases show crawlers may index the Challenge interstitial page (HTTP 202) instead of actual content during DDoS events, severely damaging SEO rankings
- Bot Control's `bot:verified` label can identify verified crawlers, but Bot Control must be placed last in the rule chain (cost optimization), and by then AntiDDoS AMR has already evaluated the request
{state_note}
**Recommendation**:
- Add an ASN + UA crawler labeling rule before AntiDDoS AMR to label Google (ASN 15169), Bing (ASN 8075), and other crawlers with `crawler:verified` (full rule JSON in Appendix A)
- Add a scope-down to AntiDDoS AMR excluding the `crawler:verified` label

---
""",
"bot_control_search_allow": """## Issue {n} (Low): Bot Control CategorySearchEngine/CategorySeo overridden to Allow

**Rule**: {rule_name} (priority {priority})
**Current state**: `{override_names}` overridden to Allow

**Problem**:
- These Allow overrides only affect "unverified" search engine bots: requests claiming to be search engine crawlers but failing reverse DNS verification
- Real Googlebot/Bingbot (verified) are already not blocked by these rules. They pass through with `bot:verified` label regardless of the override
- Forged Googlebot UAs (reverse DNS fails) do NOT match `CategorySearchEngine`. They fall through to `SignalNonBrowserUserAgent` and are Blocked, regardless of the override
- The Allow override lets unverified search engine bots bypass all later WAF rules. The blast radius is limited, but the override isn't needed

**Recommendation**:
- Remove the Allow overrides on `{override_names}`, restore default Block
- For SEO protection during DDoS events, use the ASN + UA crawler labeling rule (see Appendix A) instead of Bot Control Allow overrides

---
""",
"duplicate_rules": """## Issue {n} (Low): {count} group(s) of identical rules

{rule_line}
**Current state**: Rules that differ only in name and priority

**Problem**:
- The first rule in each group already decides every request it matches, so the later copies change nothing. They cost WCU and have to be kept in sync by hand. A copy of a rule group billed per request (Bot Control, Anti-DDoS, ATP, ACFP) is billed again for every request it inspects
{groups}

**Recommendation**:
- Delete the later copy in each group. The Web ACL behaves the same afterwards, because the earlier copy runs first
- Check CloudWatch alarms and dashboards that use the deleted rules' metric names
- If two copies are meant to differ, change the conditions so they actually do

---
""",
"missing_always_on_challenge": """## Issue {n} (Medium): Missing Always-on Challenge, so DDoS protection waits for reactive detection

**Rule**: N/A (missing rule)
**Current state**: No Always-on Challenge rules for landing pages in the Web ACL

**Problem**:
- All reactive protections (AntiDDoS AMR, rate-based rules) have an inherent delay between attack start and mitigation activation
- Always-on Challenge is proactive. It continuously requires browser verification on landing page paths, filtering non-browser attack traffic from the first request with zero detection delay
- Without Always-on Challenge, non-browser DDoS traffic can reach the origin unimpeded during the detection delay window

**Recommendation**:
- Add two rules to implement Always-on Challenge (see Appendix C):
  1. Count+Label rule: match landing page URIs (`/`, `/login`, `/signup`, etc.), add label `custom:landing-page`
  2. Challenge rule: match `custom:landing-page` label, apply Challenge action; exclude `crawler:verified` label (requires crawler labeling rule from Appendix A)
- Set Challenge rule token immunity time to at least 4 hours (14400 seconds) to minimize impact on real users

---
""",
"forgeable_exemptions": """## Issue {n} ({severity}): Protections skip requests that carry a value any client can send

{rule_line}
**Current state**: These rules leave out requests by a negated condition on request content

**Problem**:
{details}
- The exemption doesn't depend on the path or host, so a client that adds the value skips the protection on any request

**Recommendation**:
- Base the exemption on something the client can't set: an IP set, an ASN, or a label from an earlier rule that uses one
{crawler_rec}- If it works around a false positive in a managed rule group, don't exempt in the scope-down. Override the misfiring rule to Count, then add a rule after the group that blocks its label on every path except the affected one
- Otherwise, limit the exemption to the paths and hosts that need it

---
""",
"dead_patterns": """## Issue {n} (Low): Patterns that can never match

{rule_line}
**Current state**: Conditions with patterns no request can match

**Problem**:
{details}

**Recommendation**:
{recs}

---
""",
"noop_overrides": """## Issue {n} (Awareness): Rule overrides that set the default action

{rule_line}
**Current state**: Managed rules overridden to the action they already have

**Problem**:
{details}
- These overrides change nothing. They can hide intent: a reader may think the rule was changed

**Recommendation**:
- Remove them, or note in the rule group description why they're there

---
""",
"no_ip_rate_limit": """## Issue {n} (Medium): No per-IP rate limit covers all traffic

{rule_line}
**Current state**: This Web ACL allows by default, and no rate-based rule counts per IP across all paths with an action other than Count

**Problem**:
- A single IP can send as many requests as it wants{other}
{counted}
**Recommendation**:
- Add a per-IP rate limit on all traffic with Block, starting in Count to find the peak of real users (shared NAT and corporate egress IPs are the high end). Exempt verified crawlers with the `crawler:verified` label from Appendix A, not User-Agent strings

---
""",
"rate_challenge": """## Issue {n} (Low): Rate limits that a Challenge token lets through

{rule_line}
**Current state**: Rate-based rules whose action is Challenge or CAPTCHA

**Problem**:
{details}

**Recommendation**:
- Add a second rule on the same traffic with a higher limit and Block, so a client that solves the Challenge is still limited

---
""",
"rate_shared": """## Issue {n} (Low): Rate limits where every matching client shares one count

{rule_line}
**Current state**: Rate-based rules that count by a constant or by keys without the client IP

**Problem**:
{details}

**Recommendation**:
{recs}
---
""",
"unused_labels": """## Issue {n} (Awareness): Labels no rule uses

{rule_line}
**Current state**: Rules add labels that no later rule matches

**Problem**:
{details}
- A label only matters when a later rule matches it. These show up in logs and metrics only

**Recommendation**:
- If a rule was meant to act on the label, add it after the producing rule. Otherwise the labels are fine for observation

---
""",
"alb_always_on": """## Issue {n} (Awareness): ALB resource-level DDoS protection is set to Always on ⏳

{rule_line}
**Current state**: `OnSourceDDoSProtectionConfig.ALBLowReputationMode` is `ALWAYS_ON`

**Problem**:
- On an ALB, this rate-limits requests from known low-reputation sources all the time, checking both the client IP and IPs in `X-Forwarded-For`. AWS notes it can affect legitimate traffic more than the default, Active under DDoS
- It doesn't appear in WAF logs or labels. What it drops shows only in the ALB's `LowReputationPacketsDropped` and `LowReputationRequestsDenied` CloudWatch metrics, so a request it stopped looks like no WAF rule acted on it

**Recommendation**:
- If users reach the ALB through shared proxies, or through a proxy or CDN that sets `X-Forwarded-For`, check those metrics for drops of real traffic
- Unless there's a reason for Always on, switch to the default, Active under DDoS. The setting applies to every ALB this Web ACL is associated with

---
""",
"broad_regex": """## Issue {n} (Low): Regex conditions match more than they spell out ⏳

{rule_line}
**Current state**: Block, Challenge, or CAPTCHA rules with regex patterns whose alternatives or character classes are wider than the words in them suggest

**Problem**:
{details}

**Recommendation**:
{recs}
- Before changing a pattern, check in sampled requests or logs what it matches today, and test the new one in Count first

---
""",
"empty_sets": """## Issue {n} (Low): Referenced IP sets or regex pattern sets are empty ⏳

{rule_line}
**Current state**: The sets these rules use have no addresses or patterns

**Problem**:
{details}

**Recommendation**:
- If something fills these sets later (automation, an incident runbook), no change is needed. Check that it still runs
- Otherwise fill the sets with what the rules are meant to match, or remove the rules

---
""",
"rule_group_count": """## Issue {n} (Low): Rule groups set to Count by the Web ACL ⏳

{rule_line}
**Current state**: Rule group references with `OverrideAction` Count, or with rules overridden to Count in `RuleActionOverrides`

**Problem**:
{details}

**Recommendation**:
- If the Count is a test, check the matches in sampled requests or logs, then remove the override
- To test a whole group, override each of its rules to Count in `RuleActionOverrides` instead of setting the group's `OverrideAction` to Count. The group then runs every rule and adds every label
- If a rule has false positives, fix the rule in the rule group instead of keeping the override

---
""",
"unreviewed_refs": """## Issue {n} (Awareness): Rule groups or sets this Web ACL references weren't reviewed ⏳

{rule_line}
**Current state**: These rules reference rule groups, IP sets, or regex pattern sets by ARN; their contents weren't provided

**Problem**:
{details}

**Recommendation**:
- Export them with these read-only calls, then run the review again with the files:

```bash
{commands}
```

---
""",
"security_automations": """## Issue {n} (Awareness): Rules and IP sets from Security Automations for AWS WAF, which retires in December 2026

{rule_line}
**Current state**: These rules, or the IP sets they use, carry the Security Automations naming

**Problem**:
- AWS retires the Security Automations for AWS WAF solution in December 2026. Deployments keep running, but maintenance becomes yours
- Deleting the solution's CloudFormation stack deletes the IP sets it created. While this Web ACL uses them, the delete is expected to fail
- Source: https://docs.aws.amazon.com/solutions/latest/security-automations-for-aws-waf/solution-overview.html

**Recommendation**:
- Before retirement, create IP sets you manage, copy the addresses, and point these rules at them
- Check what still updates these IP sets. Replace the solution's automation with native rate-based rules and managed rule groups

---
""",
"host_exclusions": """## Issue {n} (Low): A host left out of many rules may be simpler on its own Web ACL

{rule_line}
**Current state**: The same host is excluded with a NOT(Host) condition in several rules

**Problem**:
{details}
- Each exclusion has to be kept in step as rules change, and some patterns, such as two Anti-DDoS AMR instances (Appendix B), exist only to treat this host differently

**Recommendation**:
- A Web ACL attaches to a whole distribution or load balancer, not to a host. If this host has its own distribution or load balancer, give it its own Web ACL with the rules it needs, and drop the exclusions here
- If it shares a distribution with the other hosts, the exclusions are the way to do it; keep them
- To check: {lookup}

---
""",
"managed_allow_override": """## Issue {n} (Awareness): Managed rule group has an Allow override that bypasses all later rules

**Rule**: {rule_name} (priority {priority})
**Current state**: {override_detail}

**Problem**:
- Overriding a managed rule to Allow means matching requests are immediately allowed and skip ALL remaining rules, both in the rule group and in the Web ACL
- This is the most dangerous override type; it creates a potential bypass path

**Recommendation**:
- Review whether Allow is truly needed; in most cases, Count (preserves labels, request continues) is the safer choice
- If Allow is intentional, document the business justification

---
""",
"order_issues": """## Issue {n} ({severity}): Rule order issues: {summary}

{rule_line}
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
"bot_control_version": """## Issue {n} ({severity}): {title}

{rule_line}
**Current state**: {current_version}

**Problem**:
- {detail}
- {versions_header}
{additions}
- {old_note}

**Recommendation**:
- Pin the latest static version (see the AWS Managed Rules changelog). Run it in Count first and compare labels with current traffic: 5.0 changed rule match precedence and added categories, so the same request can get different labels after the upgrade
- Subscribe to the rule group's SNS topic and add a CloudWatch alarm on `DaysToExpiry` for the pinned version

---
""",
"bot_control_behind": """## Issue {n} (Low): Bot Control isn't on the latest static version

{rule_line}
**Current state**: Pinned to {current_version}; the latest static version is {latest} ({released})

**Problem**:
- {current_version} misses the bot signatures and labels added up to {latest}
- Later versions added:
{additions}
- Bots that only the newer signatures recognize go through as unclassified

**Recommendation**:
- Pin {latest}. Run it in Count first and compare labels with current traffic
- Subscribe to the rule group's SNS topic and add a CloudWatch alarm on `DaysToExpiry` for the pinned version

---
""",
"managed_unpinned": """## Issue {n} (Low): Managed rule groups not pinned to a version

{rule_line}
**Current state**: No `Version` set on {groups}

**Problem**:
- These rule groups follow the AWS default version. AWS announces default-version changes only through each rule group's SNS topic, not in the changelog, so detection can change without any change to this Web ACL
{sqli_note}
**Recommendation**:
- Pin each rule group to a static version. Test a new version in Count before switching
- Subscribe to each rule group's SNS topic and alarm on `DaysToExpiry` for pinned versions

---
""",
"uri_fragment_fallback": """## Issue {n} ({severity}): UriFragment condition always matches, so the path restriction is void

{rule_line}
**Current state**: {rule_names} match `UriFragment` with `FallbackBehavior: MATCH`

**Problem**:
- `UriFragment` is the part of a URL after `#`. Browsers and HTTP clients don't send it to the server, so the condition falls back to MATCH on every request
{allow_note}

**Recommendation**:
- Match `UriPath` instead. Confirm the sender's real path before changing, then verify its requests still pass

---
""",
"uri_path_pitfalls": """## Issue {n} ({severity}): URI path conditions that can't match what they were written for

{rule_line}
**Current state**: Conditions on `UriPath` whose pattern can't match the requests it was written for

**Problem**:
{details}

**Recommendation**:
{recs}
- Test the fix in a Count copy of the rule, keeping the original in place, then replace the original once the copy matches what it should

---
""",
"path_block_decoding": """## Issue {n} ({severity}): Path or query rules don't decode like the origin, so rewritten requests slip through

{rule_line}
**Current state**: These Block rules, rate limits, or Count rules that feed a Block rule match the URI path or query string with the text transformations listed below

**Problem**:
- WAF inspects the URI path exactly as the client sent it unless a text transformation changes it, and CloudFront forwards the raw path to the origin. A request that the origin resolves to a blocked path, but that the rule doesn't see as that path, gets through. Where a rewrite could be tested, the requests below reach the origin with no Block rule in this Web ACL stopping them
{details}

**Recommendation**:
{recs}
- Each text transformation adds 10 WCU. Appendix G compares this chain with stricter and looser ones and explains which rules must not decode
- More decoding can match legitimate requests that carry encoded characters. Test the change in a Count copy of the rule and keep the original in place until the copy looks right
- Test whether the origin decodes paths. If it doesn't, the practical risk is lower

---
""",
"bot_control_inert": """## Issue {n} (Low): {title}

{rule_line}
**Current state**: {level} level, {counted} rules overridden to Count

**Problem**:
- Bot Control is billed for every request it inspects, but here it blocks nothing and no later rule matches its labels. It only adds labels and Count metrics
{remaining}
**Recommendation**:
- If it's in Count to watch before blocking, review its labels and Count metrics, then set the rules that should act back to their default actions
- If nothing will act on it, remove it, or {scope} to the traffic you plan to act on

---
""",
"unknown_overrides": """## Issue {n} (Low): Bot Control overrides name rules the group doesn't have

{rule_line}
**Current state**: Overrides for {names}

**Problem**:
- {detail}

**Recommendation**:
- Remove these overrides. If the intent was to change what replaced them, override the rules that exist now (the Bot Control rule list in the AWS WAF Developer Guide)

---
""",
"duplicate_metrics": """## Issue {n} (Awareness): Rules share a CloudWatch metric name

{rule_line}
**Current state**: Several rules use the same `MetricName`

**Problem**:
- CloudWatch rule metrics use the metric name as their `Rule` dimension, so these rules report to one metric. Its counts mix their matches, and an alarm or dashboard on it can't tell which rule fired. Sampled requests are looked up by metric name too
{details}
- WAF logs still record which rule matched

**Recommendation**:
- Give each rule its own `MetricName`. Renaming a rule doesn't change its metric name

---
""",
"sensitive_files": """## Issue {n} (Low): No rule blocks sensitive-file probes such as `{first}`

**Rule**: N/A (missing rule)
**Current state**: This Web ACL allows traffic by default, and no rule in it blocks {paths}

**Problem**:
- Scanners request these paths on every site they find. If the origin serves one, the file gets downloaded: dotfiles, backups, and dumps can give away source code or credentials
{gaps}
**Recommendation**:
- Keep these files out of the web root, or deny dotfiles at the origin. WAF is the second layer
{linux}{custom}- If the site serves any of these paths on purpose, exempt them before switching to Block

---
""",
"path_only_allow": """## Issue {n} ({severity}): Allow rules match only on request content, with no IP or other unforgeable condition

{rule_line}
**Current state**: {rule_names} allow requests by path (and other request content) alone

**Problem**:
- Anyone who knows or guesses the path gets the request straight to the origin. Allow ends evaluation, so no later rule inspects it
{acl_note}
**Recommendation**:
- Add the sender's IP set where the sender publishes egress IPs
- Otherwise the application must verify request signatures, and content inspection (CRS, KnownBadInputs) scoped to these paths should run before the Allow rules
- Use `EXACTLY`, or a `STARTS_WITH` value as specific as possible
{trav_rec}
---
""",
"managed_count": """## Issue {n} (Medium): Managed protections left in Count

{rule_line}
**Current state**: Managed rule groups, or rules inside them, set to Count

**Problem**:
{details}
- Count only records metrics and labels, it doesn't block. `SizeRestrictions_BODY` and `HostingProviderIPList` in Count are common deliberate choices and aren't listed here

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

{rule_line}
**Current state**: {stmt_summary}，action 为 Allow，无 scope-down

**Problem**:
- {forgeable_fields} 是完全可伪造的，任何客户端只要带上{forgeable_example}，就能跳过后面所有规则{skipped}
- 该规则的 blast radius 是全局的：所有路径都受影响，没有 host 或 URI 限制
{notes}
**Recommendation**:
{recs}
---
""",
"hosting_provider_allow": """## Issue {n} ({severity}): HostingProviderIPList 被覆盖为 Allow，云主机流量会跳过所有后续规则

**Rule**: {rule_name} (priority {priority})
**Current state**: `HostingProviderIPList` 规则被覆盖为 Allow{scope_state}

**Problem**:
- `HostingProviderIPList` 默认 Block 云托管和 Web 托管提供商的 IP。覆盖为 Allow 后，来自这些 IP 的请求直接放行，后面的规则都不再检查
- 现代 DDoS 攻击大量使用云托管基础设施（VPS、云函数、容器）。Allow 覆盖让这些攻击流量完全绕过 IP 信誉、Bot Control、速率限制等所有保护
- 正确做法是覆盖为 Count（保留标签，供下游规则使用），而非 Allow
{scope_note}
**Recommendation**:
- 将 `HostingProviderIPList` 的覆盖从 Allow 改为 Count
- 如果担心企业用户通过云代理访问时被误封，Count 模式已经解决了这个问题（不会 Block，只添加标签）

---
""",
"scope_down_too_narrow": """## Issue {n} (Medium): IP 信誉和匿名 IP 规则组的 scope-down 过窄，仅检查首页

{rule_line}
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

{rule_line}
**Current state**: 对 API 路径和/或 POST 请求应用 Challenge action

**Problem**:
- Challenge 只能由浏览器 GET 请求完成（需要执行 JavaScript 并接受 HTML 响应）
- API 路径通常由原生 App 或 JavaScript fetch/XHR 访问，无法完成 Challenge
- POST 请求无法完成 Challenge：客户端会收到 HTTP 202 但无法重新提交原始 POST 请求
- 实际效果：这些规则对 API 客户端和原生 App 等同于 Block

**Recommendation**:
- 对 API 滥用防护：考虑改用速率限制（rate-based rule）而非 Challenge
- 对 POST 端点：应在对应的 GET 页面（landing page）上应用 Challenge，而不是在 POST 请求上
{dup_rec}
---
""",
"missing_baseline": """## Issue {n} ({severity}): 缺少 {missing_names} 基线防护规则组

**Rule**: N/A (缺失规则)
**Current state**: Web ACL 中没有 {missing_names}

**Problem**:
- {missing_detail}

**Recommendation**:
{missing_rec}

---
""",
"token_domain": """## Issue {n} (Low): Token Domain 配置包含冗余子域名

**Rule**: N/A (Web ACL 全局配置)
**Current state**: token_domains 包含 {domain_list}

**Problem**:
- Token Domain 使用后缀匹配，`{apex}` 自动覆盖所有子域名
- 列出子域名是冗余的，不会造成安全问题，但增加了配置维护成本

**Recommendation**:
- 仅保留 `{apex}`，删除其他子域名条目

---
""",
"no_logging": """## Issue {n} (Awareness): 导出里看不到 WAF 日志配置

**Rule**: N/A (Web ACL 全局配置)
**Current state**: WAF JSON 导出不带日志配置

**Problem**:
- 导出文件不带日志配置，所以这条只说明没法确认，不代表日志没开
- 查安全事件、调规则、排查误报，都要靠 WAF 日志

**Recommendation**:
- 在 AWS 控制台或用 CLI 确认 WAF 日志有没有开（Amazon Data Firehose、S3 或 CloudWatch Logs）
- 日志至少留 90 天，再给关键指标（Block 率、Challenge 率）配上 CloudWatch 告警

---
""",
"logging_disabled": """## Issue {n} (Awareness): 未启用 WAF 日志

**Rule**: N/A (Web ACL 全局配置)
**Current state**: `get-logging-configuration` 显示该 Web ACL 没有日志配置

**Problem**:
- 没有请求日志，被 Block 或 Challenge 的请求事后无法追查
- 排查误报、调规则、调查安全事件时，只能依赖采样请求和 CloudWatch 指标

**Recommendation**:
- 启用 WAF 日志，目标可选 CloudWatch Logs、S3 或 Amazon Data Firehose
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
"count_without_labels": """## Issue {n} (Awareness): {rule_names} 是不打标签的 Count 规则，只产生指标

{rule_line}
**Current state**: 动作是 Count，没有 RuleLabels

**Problem**:
- 不打标签的 Count 规则只产生 CloudWatch 指标，后面的规则用不上它的匹配结果
- 如果本意是对命中的请求做点什么，现在的配置做不到

**Recommendation**:
- 只是用来观察的话，把名字改得能看出用途
- 要对命中的请求采取动作（Block、Challenge 等），就改动作，或者加上标签给后面的规则用
- 除非条件伪造不了（比如 IP set），不要改成 Allow：按 User-Agent 或 header 放行，任何客户端都能借它跳过后面所有规则

---
""",
"challenge_all_during_event": """## Issue {n} ({severity}): ChallengeAllDuringEvent 被覆盖为 Count，DDoS 事件期间的兜底 Challenge 关掉了

**Rule**: {rule_name} (priority {priority})
**Current state**: `ChallengeAllDuringEvent` 被覆盖为 Count

**Problem**:
- `ChallengeAllDuringEvent` 是 AntiDDoS AMR 兜底的软缓解。检测到 DDoS 事件时，它对所有可 Challenge 的请求发起 Challenge，不管是否可疑，用来过滤不能执行 JavaScript 的攻击工具
- 覆盖为 Count 后，事件期间这条规则只产生指标，不做任何缓解
{details}

**Recommendation**:
- **最佳方案**：如果架构支持，使用前后端分离：前端 Web ACL（浏览器流量）启用 ChallengeAllDuringEvent 默认配置；后端 Web ACL（API/原生 App 流量）关闭 Challenge，提高 Block 灵敏度
- **如果前后端共用同一域名**：在同一 Web ACL 中部署双 AMR 实例，一个针对浏览器流量（启用 ChallengeAllDuringEvent），另一个针对 API/原生 App 流量（禁用 Challenge，Block 灵敏度 MEDIUM）。实现步骤见附录 B
- 不推荐"单实例 + 全部 Count + 自定义标签规则"方案：需要理解 6+ 个 AMR 标签的语义，Count 覆盖会禁用 AMR 内置联动逻辑，且仍需回答"哪些路径可以 Challenge"

---
""",
"dead_exempt_regex": """## Issue {n} ({severity}): AntiDDoS AMR 豁免正则里以 `^/` 开头的分支永远匹配不上，这些路径照样会被 Challenge

**Rule**: {rule_name} (priority {priority})
**Current state**: 豁免正则 `{regex}`

**Problem**:
- AWS WAF 拿豁免正则去匹配"host 加规范化后的路径"，比如 `www.example.com/api/orders`，所以以 `^/` 开头的分支永远匹配不上：{dead_list}
- 这些路径上的 GET 请求没有被豁免，DDoS 事件期间会被 {challenge_rules} Challenge。API 和原生 App 客户端过不了 Challenge，这些请求会失败。只有 GET 请求会被 Challenge
{state_note}
**Recommendation**:
- 锚定在 host 后面：{suggestion}。`^[^/]+` 代表任意 host；只想豁免某个 host，就写出 host 本身（`^api\\.example\\.com\\/`）
- 匹配前路径结尾的 `/` 会被去掉，所以 `\\/api\\/` 匹配不到 `/api` 本身，`\\/api(\\/|$)` 可以
- 用 WAF 日志确认效果：被豁免的请求没有 `awswaf:managed:aws:anti-ddos:challengeable-request` 标签，这个标签平时就会打，不用等 DDoS 事件

---
""",
"unanchored_exempt_regex": """## Issue {n} ({severity}): AntiDDoS AMR 的豁免 URI 正则没有锚定，攻击者构造路径就能跳过 Challenge

**Rule**: {rule_name} (priority {priority})
**Current state**: 豁免正则 `{regex}`，路径分支没有锚定

**Problem**:
- AWS WAF 拿豁免正则去匹配"host 加规范化后的路径"。下面这些分支没有锚定，在其中任何位置出现都算匹配：{unanchored_list}
- 攻击者可以构造包含这些关键词的任意路径，让 {challenge_rules} 跳过这些请求，例如：{examples}
- 这样，攻击请求在 DDoS 事件期间也能免于 Challenge
{state_note}
**Recommendation**:
- 把这些分支锚定在 host 后面：{suggestion}。`^[^/]+` 代表任意 host；只想豁免某个 host，就写出 host 本身（`^api\\.example\\.com\\/`）。不要用 `^/` 锚定：字符串是从 host 开始的，这样的分支永远匹配不上
- 先确认真实路径。如果 API 挂在 `/v1/` 这样的前缀下，要把前缀写进去（`^[^/]+\\/v1\\/query`），否则锚定后的分支就匹配不上了
- 静态资源后缀匹配（比如 `\\.(css|js|png)$`）已经用 `$` 锚定，不用改

---
""",
"missing_crawler_labeling": """## Issue {n} ({severity}): 缺少爬虫标记规则，DDoS 事件期间搜索引擎爬虫可能被 Challenge

**Rule**: N/A (缺失规则)
**Current state**: Web ACL 中没有 ASN + UA 爬虫标记规则

**Problem**:
- `ChallengeAllDuringEvent` 会在 DDoS 事件期间对所有可 Challenge 的请求发起 Challenge，包括搜索引擎爬虫（Googlebot、Bingbot 等）
- 真实案例表明，爬虫在 DDoS 事件期间可能索引 Challenge 拦截页（HTTP 202）而非实际内容，严重损害 SEO 排名
- Bot Control 的 `bot:verified` 标签虽然可以识别已验证爬虫，但 Bot Control 必须放在规则链末尾（成本优化），此时 AntiDDoS AMR 已经评估完毕，无法使用该标签
{state_note}
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
- 真正的 Googlebot/Bingbot（已验证）本来就不会被这两个规则 Block，它们带着 `bot:verified` 标签直接放行，与覆盖无关
- 伪造 Googlebot UA 的攻击者不会匹配 `CategorySearchEngine`（反向 DNS 验证失败后落入 `SignalNonBrowserUserAgent`），也与覆盖无关
- Allow 覆盖让未验证的搜索引擎 Bot 绕过所有后续 WAF 规则，虽然 blast radius 有限，但并非必要

**Recommendation**:
- 移除 `{override_names}` 的 Allow 覆盖，恢复默认 Block
- 如果担心 DDoS 事件期间爬虫被 Challenge 影响 SEO，正确做法是添加 ASN + UA 爬虫标记规则（见附录 A），而不是在 Bot Control 中使用 Allow 覆盖

---
""",
"duplicate_rules": """## Issue {n} (Low): 有 {count} 组规则完全相同

{rule_line}
**Current state**: 这些规则除了名字和 priority，其他配置完全一样

**Problem**:
- 每组里排在前面的规则已经决定了它匹配到的请求怎么处理，后面的副本不会改变任何结果，只是多占 WCU，改规则时还得记得两边一起改。按请求计费的规则组（Bot Control、Anti-DDoS、ATP、ACFP）有副本的话，副本检查的每个请求都要再收一次费
{groups}

**Recommendation**:
- 每组删掉排在后面的那条。前面那条先执行，删掉后 ACL 的行为不变
- 检查有没有 CloudWatch 告警或仪表盘用到被删规则的指标名
- 如果两条本来就想做不同的事，把条件改成真正不一样

---
""",
"missing_always_on_challenge": """## Issue {n} (Medium): 缺少 Always-on Challenge，DDoS 防护依赖响应式检测的延迟窗口

**Rule**: N/A (缺失规则)
**Current state**: Web ACL 中没有针对 landing page 的 Always-on Challenge 规则

**Problem**:
- 所有响应式防护（AntiDDoS AMR、速率限制规则）在攻击开始到缓解生效之间都存在不可避免的检测延迟窗口
- Always-on Challenge 是主动式防护：对 landing page 路径持续要求浏览器验证，无需等待攻击检测，从第一个请求起即过滤无法执行 JavaScript 的攻击工具
- 缺少 Always-on Challenge 意味着在检测延迟窗口内，大量非浏览器攻击流量可以无阻碍地到达源站

**Recommendation**:
- 添加两条规则实现 Always-on Challenge（实现步骤见附录 C）：
  1. Count+Label 规则：匹配 landing page URI（`/`、`/login`、`/signup` 等），添加标签 `custom:landing-page`
  2. Challenge 规则：匹配 `custom:landing-page` 标签，应用 Challenge action；在条件中排除 `crawler:verified` 标签（需先实现爬虫标记规则）
- 将 Challenge 规则的 token immunity time 设置为至少 4 小时（14400 秒），避免真实用户频繁被 Challenge

---
""",
"forgeable_exemptions": """## Issue {n} ({severity}): 防护会跳过带某个值的请求，这个值任何客户端都能发

{rule_line}
**Current state**: 这些规则用一个针对请求内容的 NOT 条件，把一部分请求排除在外

**Problem**:
{details}
- 这个排除条件跟路径和 host 无关，客户端只要带上这个值，任何请求都能跳过这项防护

**Recommendation**:
- 排除条件改用客户端改不了的东西：IP set、ASN，或者由使用这些条件的前置规则打上的标签
{crawler_rec}- 如果是为了绕开托管规则组的误报，不要在 scope-down 里排除。把误报的规则改成 Count，再在规则组后面加一条规则，除了受影响的路径，其他路径上命中它的标签就 Block
- 其他情况，把排除条件限定在真正需要的路径和 host 上

---
""",
"dead_patterns": """## Issue {n} (Low): 有些匹配模式永远匹配不上

{rule_line}
**Current state**: 有些条件里的模式，没有任何请求能匹配上

**Problem**:
{details}

**Recommendation**:
{recs}

---
""",
"noop_overrides": """## Issue {n} (Awareness): 有些 override 设成了规则本来的默认动作

{rule_line}
**Current state**: 托管规则被 override 成它本来就有的动作

**Problem**:
{details}
- 这些 override 什么也没改，反而容易让人以为这条规则被调整过

**Recommendation**:
- 删掉它们，或者在规则组的描述里写清楚为什么要保留

---
""",
"no_ip_rate_limit": """## Issue {n} (Medium): 没有覆盖全部流量的按 IP 限速

{rule_line}
**Current state**: 这个 ACL 默认放行，没有一条覆盖所有路径、动作不是 Count 的按 IP 限速规则

**Problem**:
- 单个 IP 发多少请求都不会被限{other}
{counted}
**Recommendation**:
- 加一条覆盖所有流量、按 IP 计数、动作为 Block 的限速。先用 Count 看正常用户的峰值（共享 NAT 和公司出口 IP 最高）。验证过的爬虫用附录 A 的 `crawler:verified` 标签排除，不要按 User-Agent 字符串排除

---
""",
"rate_challenge": """## Issue {n} (Low): 有些限速拿到 Challenge token 就能绕过

{rule_line}
**Current state**: 限速规则的动作是 Challenge 或 CAPTCHA

**Problem**:
{details}

**Recommendation**:
- 在同一批流量上再加一条阈值更高、动作为 Block 的限速，让通过 Challenge 的客户端也会被限

---
""",
"rate_shared": """## Issue {n} (Low): 有些限速让所有匹配的客户端共用一个计数

{rule_line}
**Current state**: 限速规则按常量，或按不含客户端 IP 的键计数

**Problem**:
{details}

**Recommendation**:
{recs}
---
""",
"unused_labels": """## Issue {n} (Awareness): 有些标签没有规则在用

{rule_line}
**Current state**: 规则加了标签，但后面没有规则匹配它

**Problem**:
{details}
- 只有后面的规则匹配标签时，标签才起作用。这些标签只会出现在日志和指标里

**Recommendation**:
- 如果本来想根据这个标签采取动作，在产生它的规则后面补上对应的规则；只是用来观察的话，保持现状就行

---
""",
"alb_always_on": """## Issue {n} (Awareness): ALB 资源级 DDoS 防护设成了 Always on ⏳

{rule_line}
**Current state**: `OnSourceDDoSProtectionConfig.ALBLowReputationMode` 是 `ALWAYS_ON`

**Problem**:
- 关联到 ALB 时，它会一直对已知低信誉来源的请求限速，既看客户端 IP，也看 `X-Forwarded-For` 里的 IP。AWS 说明它对正常流量的影响比默认的 Active under DDoS 更大
- 它不会出现在 WAF 日志和标签里，拦掉的请求只体现在 ALB 的 `LowReputationPacketsDropped` 和 `LowReputationRequestsDenied` 这两个 CloudWatch 指标里。被它挡掉的请求，看起来就像没有任何 WAF 规则处理过

**Recommendation**:
- 如果用户经过共享代理访问 ALB，或者前面有会设置 `X-Forwarded-For` 的代理或 CDN，先看看这两个指标里有没有正常流量被丢
- 没有特别理由的话，改回默认的 Active under DDoS。这个设置对这个 Web ACL 关联的所有 ALB 都生效

---
""",
"broad_regex": """## Issue {n} (Low): 正则条件匹配得比字面更宽 ⏳

{rule_line}
**Current state**: Block、Challenge 或 CAPTCHA 规则里的正则，分支或字符类比里面的字看起来要宽

**Problem**:
{details}

**Recommendation**:
{recs}
- 改模式之前，先在 sampled requests 或日志里看它现在命中了什么，新模式先用 Count 试

---
""",
"empty_sets": """## Issue {n} (Low): 引用的 IP set 或 regex pattern set 是空的 ⏳

{rule_line}
**Current state**: 这些规则用到的 set 里没有地址，也没有正则

**Problem**:
{details}

**Recommendation**:
- 如果有东西会往这些 set 里填（自动化脚本、应急预案），不用改，确认它还在运行就行
- 否则按规则的用途把 set 填上，或者删掉这些规则

---
""",
"rule_group_count": """## Issue {n} (Low): Web ACL 把 rule group 设成了 Count ⏳

{rule_line}
**Current state**: rule group 引用的 `OverrideAction` 是 Count，或者在 `RuleActionOverrides` 里把组内规则改成了 Count

**Problem**:
{details}

**Recommendation**:
- 如果 Count 是在测试，先在 sampled requests 或日志里看匹配情况，再去掉 override
- 要测试整个组，用 `RuleActionOverrides` 把组里每条规则改成 Count，不要把组的 `OverrideAction` 设成 Count。这样组里每条规则都会执行，每个标签都会打上
- 如果某条规则有误报，直接在 rule group 里改这条规则，不要一直靠 override

---
""",
"unreviewed_refs": """## Issue {n} (Awareness): 这个 Web ACL 引用的 rule group 或 set 没有审到 ⏳

{rule_line}
**Current state**: 这些规则按 ARN 引用了 rule group、IP set 或 regex pattern set，评审时没拿到它们的内容

**Problem**:
{details}

**Recommendation**:
- 用下面的只读命令导出这些资源，再带上导出的文件重新评审：

```bash
{commands}
```

---
""",
"security_automations": """## Issue {n} (Awareness): 这些规则和 IP set 来自 Security Automations for AWS WAF，这个方案 2026 年 12 月退役

{rule_line}
**Current state**: 这些规则或它们引用的 IP set 用的是 Security Automations 的命名

**Problem**:
- AWS 会在 2026 年 12 月退役 Security Automations for AWS WAF。已有部署会继续运行，但之后要自己维护
- 删除这个方案的 CloudFormation 栈时，会删除它创建的 IP set。本 Web ACL 还在用这些 IP set，删除预计会失败
- 来源：https://docs.aws.amazon.com/solutions/latest/security-automations-for-aws-waf/solution-overview.html

**Recommendation**:
- 退役前新建自己管理的 IP set，把名单复制过去，再把这些规则改成引用新的 IP set
- 确认现在是谁在更新这些 IP set。方案里的自动化功能，改用原生的限速规则和托管规则组替代

---
""",
"host_exclusions": """## Issue {n} (Low): 被很多规则排除的 host，单独用一个 Web ACL 可能更简单

{rule_line}
**Current state**: 同一个 host 在多条规则里用 NOT(Host) 条件排除

**Problem**:
{details}
- 每条排除条件都要跟着规则一起维护。有些做法，比如两个 Anti-DDoS AMR 实例（附录 B），只是为了单独处理这个 host

**Recommendation**:
- Web ACL 是关联到整个 distribution 或负载均衡上的，不能按 host 关联。如果这个 host 有自己的 distribution 或负载均衡，给它单独建一个 Web ACL，只放它需要的规则，这里的排除条件就可以删掉
- 如果它和其他 host 共用一个 distribution，排除条件就是正确的做法，保留即可
- 确认方法：{lookup}

---
""",
"managed_allow_override": """## Issue {n} (Awareness): 托管规则组存在 Allow 覆盖，匹配的请求会绕过所有后续规则

**Rule**: {rule_name} (priority {priority})
**Current state**: {override_detail}

**Problem**:
- 将托管规则覆盖为 Allow 意味着匹配的请求将被立即放行，跳过所有后续规则，包括同一规则组内和 Web ACL 中的所有规则
- 这是最危险的覆盖类型，会创建潜在的绕过路径

**Recommendation**:
- 评估是否真正需要 Allow；大多数情况下，Count（保留标签，请求继续评估）是更安全的选择
- 如果 Allow 是有意为之，请记录业务理由

---
""",
"order_issues": """## Issue {n} ({severity}): 规则顺序问题，{summary}

{rule_line}
**Current state**: 现有规则的评估顺序，影响到了哪些请求会被检查或拦截

**Problem**:
{problems}

**Recommendation**:
{recs}
- 新增规则类型时放在哪个位置，参考附录 D

---
""",
"recommended_protections": """## Issue {n} ({severity}): 建议补充的防护：{names}

**Rule**: N/A (缺失规则)
**Current state**: 这个 ACL 默认放行，面向公网流量，但没有部署这些防护

**Problem**:
{problems}

**Recommendation**:
{recs}
- 每一项都先用 Count 加进去，看清楚命中的是什么流量，再切回默认动作

---
""",
"bot_control_version": """## Issue {n} ({severity}): {title}

{rule_line}
**Current state**: {current_version}

**Problem**:
- {detail}
- {versions_header}
{additions}
- {old_note}

**Recommendation**:
- 固定到最新的静态版本（见 AWS Managed Rules changelog）。先用 Count 跑一段时间，对比升级前后的标签：5.0 调整了规则的匹配顺序并新增了类别，同一个请求升级后可能命中不同的标签
- 订阅规则组的 SNS 主题，并给固定的版本设置 `DaysToExpiry` 的 CloudWatch 告警

---
""",
"bot_control_behind": """## Issue {n} (Low): Bot Control 不是最新的静态版本

{rule_line}
**Current state**: 固定在 {current_version}；最新的静态版本是 {latest}（{released}）

**Problem**:
- {current_version} 缺少截至 {latest} 新增的 bot 特征和标签
- 之后的版本新增了：
{additions}
- 只有新版本特征才认得出的 bot，现在会被当作未分类放过去

**Recommendation**:
- 固定到 {latest}。先用 Count 跑一段时间，对比升级前后的标签
- 订阅规则组的 SNS 主题，并给固定的版本设置 `DaysToExpiry` 的 CloudWatch 告警

---
""",
"managed_unpinned": """## Issue {n} (Low): 托管规则组没有固定版本

{rule_line}
**Current state**: {groups} 没有设置 `Version`

**Problem**:
- 这些规则组跟着 AWS 的默认版本走。AWS 调整默认版本时不写进 changelog，只通过各规则组的 SNS 主题通知，所以 ACL 配置没变，检测行为也可能变了
{sqli_note}
**Recommendation**:
- 给每个规则组固定一个静态版本。切换新版本前先用 Count 观察
- 订阅各规则组的 SNS 主题，给固定的版本设置 `DaysToExpiry` 告警

---
""",
"uri_fragment_fallback": """## Issue {n} ({severity}): UriFragment 条件恒为真，路径限制失效

{rule_line}
**Current state**: {rule_names} 用 `UriFragment` 做匹配，且 `FallbackBehavior: MATCH`

**Problem**:
- `UriFragment` 是 URL 里 `#` 后面的部分。浏览器和 HTTP 客户端都不会把它发给服务器，所以每个请求都会走 fallback，被当成匹配
{allow_note}

**Recommendation**:
- 改成匹配 `UriPath`。修改前先确认发送方的真实路径，改完后确认它的请求仍能正常通过

---
""",
"uri_path_pitfalls": """## Issue {n} ({severity}): 有些 URI 路径条件按现在的写法匹配不到想拦的请求

{rule_line}
**Current state**: `UriPath` 上的匹配模式和它要匹配的请求对不上

**Problem**:
{details}

**Recommendation**:
{recs}
- 先建一条修正后的 Count 副本，原规则保留，看清楚副本的命中情况，再替换原规则

---
""",
"path_block_decoding": """## Issue {n} ({severity}): 按路径或查询串匹配的规则，解码跟源站对不上，改写过的请求能绕过

{rule_line}
**Current state**: 这些 Block 规则、限速规则，或者给 Block 规则打标签的 Count 规则，按下面列出的文本转换匹配 URI 路径或查询串

**Problem**:
- 除非文本转换改写了路径，WAF 按客户端发来的原样检查它，CloudFront 也把原始路径转给源站。源站会解析成被拦路径、规则却认不出来的请求，就能过去。能模拟的地方，下面列出了到达源站、没有任何 Block 规则拦住的请求
{details}

**Recommendation**:
{recs}
- 每个文本转换 10 WCU。附录 G 对比了更严和更松的写法，也说明了哪些规则不能解码
- 解码多了，带编码字符的正常请求也可能被匹配。先建一条改好的 Count 副本观察，原规则保留，副本没问题再替换
- 测试一下源站会不会对路径做解码。如果不解码，实际风险会低一些

---
""",
"bot_control_inert": """## Issue {n} (Low): {title}

{rule_line}
**Current state**: {level} 级别，{counted} 条规则改成了 Count

**Problem**:
- Bot Control 按检查的请求数计费，但在这里它什么都不拦，后面也没有规则匹配它的标签，只是打标签、产生 Count 指标
{remaining}
**Recommendation**:
- 如果是先用 Count 观察，看过标签和 Count 指标后，把该生效的规则改回默认动作
- 如果不打算用它做任何处理，就删掉，或者{scope}

---
""",
"unknown_overrides": """## Issue {n} (Low): Bot Control 的 override 指向了规则组里不存在的规则

{rule_line}
**Current state**: 对 {names} 做了 override

**Problem**:
- {detail}

**Recommendation**:
- 删掉这些 override。如果本意是调整替代它们的规则，就对现在存在的规则做 override（规则列表见 AWS WAF Developer Guide 的 Bot Control 部分）

---
""",
"duplicate_metrics": """## Issue {n} (Awareness): 有几条规则共用同一个 CloudWatch 指标名

{rule_line}
**Current state**: 几条规则的 `MetricName` 相同

**Problem**:
- CloudWatch 的规则指标用指标名作 `Rule` 维度，这几条规则会写进同一个指标。计数混在一起，基于它的告警和看板分不出是哪条规则命中的。sampled requests 也是按指标名查的
{details}
- WAF 日志里仍然记着是哪条规则命中的

**Recommendation**:
- 给每条规则单独的 `MetricName`。改规则名不会自动改指标名

---
""",
"sensitive_files": """## Issue {n} (Low): 没有规则拦截 `{first}` 这类敏感文件探测

**Rule**: N/A (缺失规则)
**Current state**: 这个 Web ACL 默认放行，里面没有规则拦截 {paths}

**Problem**:
- 扫描器对找到的每个站点都会试这些路径。源站只要返回其中一个，文件就被下载走了：dotfile、备份和导出文件可能泄露源码或凭证
{gaps}
**Recommendation**:
- 别把这些文件放在 Web 根目录，或者在源站直接拒绝 dotfile。WAF 只是第二层
{linux}{custom}- 站点确实要提供其中某些路径的话，切 Block 之前先把它们排除掉

---
""",
"path_only_allow": """## Issue {n} ({severity}): Allow 规则只按请求内容放行，没有 IP 等不可伪造的条件

{rule_line}
**Current state**: {rule_names} 只凭路径等请求内容就放行

**Problem**:
- 任何人只要知道或猜到路径，请求就能直达源站。Allow 会终止规则评估，后面的规则都不会再检查它
{acl_note}
**Recommendation**:
- 发送方公布了出口 IP 的，补上对应的 IP set 条件
- 拿不到出口 IP 的，应用层必须校验请求签名，并在 Allow 规则前面加上限定在这些路径的内容检测（CRS、KnownBadInputs）
- 路径尽量用 `EXACTLY`，或者把 `STARTS_WITH` 的值写得更具体
{trav_rec}
---
""",
"managed_count": """## Issue {n} (Medium): 托管规则的防护处于 Count

{rule_line}
**Current state**: 托管规则组整组，或组里的部分规则，被设成了 Count

**Problem**:
{details}
- Count 只记录指标和标签，不拦截。`SizeRestrictions_BODY` 和 `HostingProviderIPList` 保持 Count 是常见的合理做法，这里没有列出

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

