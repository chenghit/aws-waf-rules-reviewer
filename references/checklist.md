# WAF Rules Review Checklist

Evaluate each item. Skip items irrelevant to the Web ACL's purpose.

Phase 1 (sections 1–16): Independent checks.
Phase 2 (sections 17–18): Global cross-checks that use Phase 1 findings as input.
Additional checks (sections 19–21): independent checks added in v0.6.

---

## Phase 1: Independent Checks

### 1. Allow Rules Audit

For every Allow rule:
- [ ] Is the matching condition forgeable? (UA, cookie, header = forgeable; IP set, WAF token, ASN = unforgeable)
- [ ] Does bypassing all subsequent rules create a security gap?
- [ ] For managed rule group Allow overrides: does the default already handle the case?
- [ ] Rule conditions combine as AND/OR/NOT. One forgeable OR branch is enough to trigger the Allow, even when another branch is an IP set (scripted)
- [ ] Fixed values in rules (device IDs, test parameters, tokens) are there on purpose, and the Web ACL config isn't public. Judge them by whether a client can send them, not by where they're stored

If a UA-based Allow rule is found, note `UA_ALLOW_FOUND` — referenced by section 5.

### 2. Scope-down Statements

For every managed rule group with a scope-down:
- [ ] Does the scope-down make the rule group ineffective? (e.g., `URI EXACTLY "/"` = only homepage checked)
- [ ] Is the scope-down too broad?
- [ ] Regex anchoring: unanchored patterns are `contains` matches
- [ ] Forgeable exemptions (scripted): a scope-down or rule condition such as `NOT(body CONTAINS 'x')` or `NOT(User-Agent matches crawler names)` lets any client skip the protection by sending that value, on any path. Random-looking values (hashes, UUIDs) count as intended secrets and aren't flagged. Medium when it lets an attack through today; Low when the rule is in Count (unless it's a Count+Label rule whose label others act on), when the Web ACL blocks by default with no later Allow, or for browser prefetch signals
- [ ] Host conditions: on CloudFront the Host header picks the distribution, and a Host that matches none is rejected, so a Host exemption means a different site. Check it anyway when several names on one distribution share an origin. Behind an ALB any Host reaches the default listener rule, so the scripts count a Host exemption as forgeable there. Don't use a Host match as the only trust boundary for an Allow

### 3. AntiDDoS AMR Configuration

- [ ] Is `ChallengeAllDuringEvent` enabled (not overridden to Count)?
- [ ] If disabled for native app reasons → recommend dual AMR instance (read antiddos-amr.md for details)
- [ ] Exempt URI regex: are API path branches anchored with `^`? Unanchored = attackers can bypass via paths containing the keyword
- [ ] Regex `|` precedence: `$` only anchors the last branch unless grouped with `()`
- [ ] **SEO**: is there a crawler labeling rule before AMR? Without it, crawlers get challenged during DDoS events (read crawler-seo.md)

### 4. Challenge Action Applicability

For every Challenge or CAPTCHA rule:
- [ ] Does it target requests that can complete Challenge? (Only browser GET text/html)
- [ ] POST/API/native app = effectively Block. Intended?
- [ ] Challenge on rate-limit for API paths: low severity if users won't exceed threshold

**Count rules with Challenge/Block intent:**
- [ ] If a Count rule's name suggests Challenge/Block intent: evaluate statement as if action were already switched. Flag as Medium if broad match would Block POST/API/native app traffic.

### 5. Bot Control Configuration

- [ ] State the inspection level the Web ACL actually uses first. COMMON only looks at the User-Agent and source IP: it catches self-identifying bots, non-browser UAs, and known bot data centers, and misses scanners that send a browser UA from a clean IP (common when a financial customer scans itself)
- [ ] Unpinned Bot Control runs AWS's current default version, whichever that is (scripted in section 12). TGT_* overrides at COMMON do nothing (scripted)
- [ ] TARGETED depends on tokens. Before recommending TARGETED, or switching TGT rules from Count to Block, check whether the site uses the application integration SDK (read bot-control.md "Targeted level without the SDKs")
- [ ] For browser-only hosts, token-based controls (Challenge, TARGETED with the JS SDK) stop scanners that don't run JavaScript, regardless of payload encoding. Bot Control doesn't block a request just for missing a token: `TGT_TokenAbsent` only counts, so blocking on `awswaf:managed:token:absent` needs a custom rule
- [ ] Allow override on category rules → lets unverified bots bypass all subsequent rules
- [ ] CategorySearchEngine/CategorySeo Allow → Low severity, limited blast radius. Correct approach: crawler labeling rule
- [ ] SignalNonBrowserUserAgent and CategoryHttpLibrary: Count when native apps, API clients, partners, or monitoring reach the Web ACL; default Block for a site only browsers use. The ACL can't prove which; ask, or write both cases
- [ ] Crawler names in UA conditions: the scripts check them against the official User-Agents in `scripts/crawler-uas.json`. For crawlers not in that file, check by hand

If `UA_ALLOW_FOUND`: native app traffic will enter Bot Control after fix.
- Short-term: scope-down Bot Control with unforgeable label (bypasses entire rule group)
- Medium-term: integrate WAF Mobile SDK (read bot-control.md for details)
- If `TGT_TokenAbsent` is overridden to Challenge, keep that override: it enforces tokens per request. Its default is Count, so a Count override is a no-op

### 6. Rate-based Rules

- [ ] Activation delay exists — not instantaneous
- [ ] Challenge on API paths = effectively Block (low severity)
- [ ] Thresholds reasonable? (payment APIs < static pages)
- [ ] Rate limiting coverage for native app traffic?
- [ ] Overlapping scope-downs: only lowest threshold triggers for overlapping traffic
- [ ] A rate rule with a scope-down blocks only requests that match the scope-down, not the whole IP. Detection takes about 20–30 seconds. WAF can't count distinct paths per IP and can't see response status codes (only ATP/ACFP inspect responses)
- [ ] Don't recommend log-driven 4xx auto-blocking for burst scanning: it acts after minutes and costs a lot to run
- [ ] No per-IP rate limit with an action other than Count on a default-Allow ACL (scripted, Medium)
- [ ] Challenge or CAPTCHA as the rate-limit action (scripted): a client with a valid token passes however fast it sends. Add a Block tier with a higher limit
- [ ] Shared counts (scripted): CONSTANT, or custom keys without the IP, put every matching client in one count. For a per-crawler budget scoped by User-Agent, forged UAs use the budget up. That's reported only when the scope matches a search engine crawler (Google, Bing, Yandex): count only the verified crawler with the Appendix A label. AI crawlers and agents don't affect SEO, so their budgets aren't a finding

### 7. IP Reputation and Anonymous IP Rules

- [ ] Are rule groups inspecting all traffic? (Check scope-down)
- [ ] AWSManagedIPDDoSList at default Count: only adds label. If no downstream rule uses it → no protection (read ip-reputation.md)
- [ ] HostingProviderIPList: default Block → override to Count. Override to Allow → dangerous.
- [ ] Missing IP reputation or anonymous IP lists on a default-Allow ACL are scripted (recommended protections). Scope anonymous IP by who the caller is: end-user hosts yes, machine-to-machine hosts no
- [ ] `AWSManagedIPReputationList`, `AWSManagedReconnaissanceList`, or `AnonymousIPList` in Count is scripted with section 20
- [ ] Rules or IP sets named after Security Automations for AWS WAF are scripted (Awareness): the solution retires in December 2026
- [ ] IP set contents (Case B, `get-ip-set`): Allow lists with ranges wider than needed, empty or stale block lists, partners and monitoring already allowed by IP

### 8. Landing Page and Cookie-based Logic

- [ ] Business cookies used for security decisions? (forgeable)
- [ ] Better: Count+Label rule on landing page URIs → always-on Challenge on labeled requests
- [ ] WAF token replaces cookie-based user detection (unforgeable)
- [ ] Exclude verified crawlers from Challenge (requires crawler labeling rule)

### 9. Missing Baseline Protections

- [ ] CRS present? If recommending: override SizeRestrictions_BODY to Count
- [ ] Body inspection limits: CloudFront inspects the first 16 KB by default (configurable up to 64 KB), ALB a fixed 8 KB. Content beyond the limit isn't inspected by any `_BODY` rule
- [ ] `SizeRestrictions_BODY` in Count is a normal choice, not a finding. If the user can list the large-body endpoints: keep it in Count and add a rule after CRS that blocks its label on other paths. Never scope down CRS for this
- [ ] Default-Block ACL: CRS/KnownBadInputs must run before the Allow rules to inspect allowed traffic (scripted)
- [ ] KnownBadInputsRuleSet present? (Log4j, Java deserialization)
- [ ] Is absence intentional? (DDoS-only Web ACL)

### 10. WCU Awareness

Remind user to verify WCU ≤ 5000 after adding recommended rules. Use `capacity`; an `actual_capacity` field in some exports isn't part of the WAF API.

### 11. Token Domain Configuration

- [ ] Apex domain covers all subdomains at any depth automatically (suffix-based matching)
- [ ] Wildcard (*) not needed

### 12. Managed Rule Group Versions

Scripted. Unpinned groups follow the AWS default version, and default changes are announced only through each group's SNS topic.
- [ ] Bot Control unpinned (AWS's current default, unknown from the config) or pinned below 5.0 → Medium; pinned to 5.0 or later but not the latest static version (6.1, `latest_versions` in managed-labels.json) → Low. 2.0/3.0 added the `TGT_TokenReuse*` rules; 4.0 Web Bot Authentication; 5.0 400+ bots and a precedence change; 6.x more signatures
- [ ] Other unpinned groups → Low. `DEFAULT_VERSION` in snake_case exports means unpinned. SQLi has two lineages: 2.0 (JSON parsing in `SQLi_BODY`) and 1.3 → 2.3 → 2.4 → 2.5
- IP reputation and anonymous IP lists are unversioned

### 13. Logging and Monitoring

Read `web_acl.logging.status` in waf-summary.json. `disabled` → logging is confirmed off. `unknown` → config wasn't supplied, remind user to verify. `enabled` → no finding.

### 14. Hashed or Opaque search_string

Retired in v0.7.4. A value stored in the Web ACL config isn't treated as leaked. Section 1 judges such values by forgeability.

### 15. Default Action

- [ ] default_action Allow or Block? CustomRequestHandling is normal.
- [ ] Redundant trailing Allow-all rule: if default is Allow and last rule is Allow-all → recommend removing

### 16. Always-on Challenge for Landing Pages

- [ ] Is there an always-on Challenge targeting landing page URIs? (read crawler-seo.md for implementation)
- [ ] Bot Control at TARGETED with `TGT_TokenAbsent` overridden to Challenge also works as an always-on Challenge, but only for requests inside Bot Control's scope-down. Scripts hand this case to you: check whether that scope covers the landing pages, and whether the labels it relies on can be forged
- [ ] A default-Allow Web ACL without Anti-DDoS AMR is handed to you here: decide whether it serves browser landing pages that need an always-on Challenge
- [ ] If absent + DDoS protection objectives → Medium severity. Recommend two-rule pattern: Count+Label on landing page URIs → Challenge on label (exclude crawlers)
- [ ] Token immunity time ≥ 4 hours (14400s)?
- [ ] Crawler labeling rule placed before Challenge rule?

---

## Phase 2: Global Cross-checks

### 17. Cross-rule and Label Dependency Analysis

**17a. Label source verification:**
- [ ] Token labels (`awswaf:managed:token:absent/accepted/rejected`, with reasons such as `rejected:not_solved`, and the same set under `awswaf:managed:captcha:`) = shared, produced by Bot Control, ATP, ACFP, AND AntiDDoS AMR. AWS doesn't document a plain Challenge or CAPTCHA rule adding them, so without one of those groups, don't rely on them
- [ ] `challengeable-request` = produced by AntiDDoS AMR
- [ ] Custom Count rules without labels → Awareness (metric-only or missing labels?). A Count rule that inserts a request header does something, so it isn't listed
- [ ] Labels a rule adds that no rule matches → Awareness (scripted)
- [ ] A host excluded with NOT(Host) by 3 or more rules → Low (scripted): a separate Web ACL is simpler if the host has its own distribution or load balancer, since a Web ACL attaches per resource, not per host. Check with `cloudfront list-distributions-by-web-acl-id` (CloudFront) or `wafv2 list-resources-for-web-acl` (regional); keep the exclusions if the hosts share a distribution

**17b. Fix impact analysis:**
- [ ] For each fix: trace affected traffic through full rule chain
- [ ] Does fix A break rule B? Remove a label? Prevent downstream rules from working?
- [ ] Document recommended fix order and simultaneous changes needed

### 18. Rule Priority Ordering

Scripted. Report only orderings with real consequences among existing rules:
- [ ] A rule matches a label that only later rules produce, or that no rule in the Web ACL adds
- [ ] A rule no request reaches: every request it matches is already ended by an earlier Allow or Block (e.g. a UA rate limit whose keywords an earlier Allow lets through). Medium when an Allow skips a protection, Low otherwise
- [ ] An IP block list runs after Allow rules
- [ ] Default-Block ACL: content inspection rule groups run after Allow rules
- [ ] Bot Control runs before rules that block or challenge on their own (cost only, Low)
- [ ] Default-Block ACL: rules after the last Allow can't change the outcome, since every request reaching them ends in Block (Low)

Missing rule types are recommended protections, not ordering problems. Use the recommended order in managed-overrides.md (Appendix D) only to say where a new rule belongs. Don't flag an intentional order, such as `block-internal-url` before an office allow list.

---

## Additional Checks

### 19. Custom Rule Matching Correctness

Scripted.
- [ ] Path Block rules, and rate limits scoped by path, without `URL_DECODE`: WAF inspects the raw path, so `/%69nternal/` bypasses `/internal/`. Recommend `URL_DECODE` ×2 → `REMOVE_NULLS` → `NORMALIZE_PATH` → `LOWERCASE`
- [ ] Allow rules with `STARTS_WITH` on the path and no `NORMALIZE_PATH`: `/prefix/../admin` matches the prefix, and reaches `/admin` if CloudFront or the origin resolves `..`
- [ ] Literal `*` in a byte match (no wildcard support)
- [ ] Query-string pattern on `UriPath` (`?`, `[?&]`): never matches
- [ ] `UriFragment` with `FallbackBehavior: MATCH`: always true, so an AND with it reduces to its other conditions
- [ ] Patterns that can never match (scripted): after LOWERCASE, a pattern with an uppercase letter (e.g. `adsBot-google`) never matches, and the reverse for UPPERCASE. A crawler name that matches none of the User-Agents the crawler publishes (`bingbot.html`; Bingbot sends `bingbot.htm`), or a robots.txt-only token, never matches either. `scripts/crawler-uas.json` holds the official User-Agents of Google, Bing, and Yandex search crawlers
- [ ] For crawler conditions on the User-Agent, the fix isn't the pattern: any client can send it. Use the `crawler:verified` label from Appendix A (ASN + User-Agent)

Managed rules inspect content as plain text (except the SQLi 2.0 lineage's JSON parsing). Encoded payloads can't all be caught by custom rules either: say so, and point to identity-based controls (IP allow lists, API key checks, tokens) and application input validation.

### 20. Protections Left in Count

Scripted.
- [ ] Whole managed rule groups in Count, including groups whose rules are all overridden to Count (checked against the latest version's rule list; a rule the running version lacks may be the only one left)
- [ ] Content rules inside CRS, KnownBadInputs, SQLi, OS, PHP, WordPress, or AdminProtection overridden to Count (except `SizeRestrictions_BODY`), and the default-Block rules of the IP reputation and anonymous IP lists (except `HostingProviderIPList`)
- [ ] Overrides that set a rule to its default action change nothing (Awareness). All rules in CRS, KnownBadInputs, SQLi, and the IP lists default to Block, except `AWSManagedIPDDoSList` (Count). In Bot Control, `TGT_TokenAbsent` defaults to Count and `TGT_VolumetricIpTokenAbsent` to Challenge
- [ ] A rule overridden to Challenge or CAPTCHA still acts; it doesn't count as "in Count"

### 21. PCI DSS

LLM. PCI DSS covers anyone who stores, processes, or transmits card data, including merchants that take card payments, not only financial companies. Decide scope first:
- The user says the customer takes card payments or is a payment or financial business → in scope
- Otherwise, `llm_context.payment_indicators` lists hosts or paths that look like payment endpoints → ask the user whether these systems are in PCI scope. If you can't ask, or until they answer, write the findings with ` ⏳`
- Neither → skip this section
- [ ] ASV scans (Requirement 11.3.2, quarterly by an ASV; 11.3.2.1 after significant change) must not be interfered with by protections that change behavior based on traffic: rate limits, auto-block IP sets, behavior-based bot rules, Challenge (ASV Program Guide v4.0 r2 section 5.6). Consistent signature and path blocking typically doesn't count. An unresolved interference makes the scan inconclusive and then failed (section 7.6)
- [ ] Recommend exceptions for the ASV's IPs on the dynamic mechanisms only, not an Allow rule at the top of the ACL
- [ ] Requirement 6.4.2: the WAF must block attacks, or alert with immediate investigation, and keep audit logs. Long-term Count rules without alerting, and unknown logging, are worth confirming with the QSA
