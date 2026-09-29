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

If a UA-based Allow rule is found, note `UA_ALLOW_FOUND` — referenced by section 5.

### 2. Scope-down Statements

For every managed rule group with a scope-down:
- [ ] Does the scope-down make the rule group ineffective? (e.g., `URI EXACTLY "/"` = only homepage checked)
- [ ] Is the scope-down too broad?
- [ ] Regex anchoring: unanchored patterns are `contains` matches

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
- [ ] Unpinned Bot Control runs the default Version_1.0 (scripted in section 12). TGT_* overrides at COMMON do nothing (scripted)
- [ ] For browser-only hosts, token-based controls (Challenge, TARGETED with the JS SDK) stop scanners that don't run JavaScript, regardless of payload encoding. Bot Control doesn't block a request just for missing a token: `TGT_TokenAbsent` only counts, so blocking on `awswaf:managed:token:absent` needs a custom rule
- [ ] Allow override on category rules → lets unverified bots bypass all subsequent rules
- [ ] CategorySearchEngine/CategorySeo Allow → Low severity, limited blast radius. Correct approach: crawler labeling rule
- [ ] SignalNonBrowserUserAgent and CategoryHttpLibrary → best practice: override to Count

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

### 7. IP Reputation and Anonymous IP Rules

- [ ] Are rule groups inspecting all traffic? (Check scope-down)
- [ ] AWSManagedIPDDoSList at default Count: only adds label. If no downstream rule uses it → no protection (read ip-reputation.md)
- [ ] HostingProviderIPList: default Block → override to Count. Override to Allow → dangerous.
- [ ] Missing IP reputation or anonymous IP lists on a default-Allow ACL are scripted (recommended protections). Scope anonymous IP by who the caller is: end-user hosts yes, machine-to-machine hosts no

### 8. Landing Page and Cookie-based Logic

- [ ] Business cookies used for security decisions? (forgeable)
- [ ] Better: Count+Label rule on landing page URIs → always-on Challenge on labeled requests
- [ ] WAF token replaces cookie-based user detection (unforgeable)
- [ ] Exclude verified crawlers from Challenge (requires crawler labeling rule)

### 9. Missing Baseline Protections

- [ ] CRS present? If recommending: override SizeRestrictions_Body to Count
- [ ] Body inspection limits: CloudFront inspects the first 16 KB by default (configurable up to 64 KB), ALB a fixed 8 KB. Content beyond the limit isn't inspected by any `_BODY` rule
- [ ] `SizeRestrictions_BODY` in Count is a normal choice, not a finding. If the user can list the large-body endpoints: keep it in Count and add a rule after CRS that blocks its label on other paths. Never scope down CRS for this
- [ ] Default-Block ACL: CRS/KnownBadInputs must run before the Allow rules to inspect allowed traffic (scripted)
- [ ] KnownBadInputsRuleSet present? (Log4j, Java deserialization)
- [ ] Is absence intentional? (DDoS-only Web ACL)

### 10. WCU Awareness

Remind user to verify WCU ≤ 5000 after adding recommended rules.

### 11. Token Domain Configuration

- [ ] Apex domain covers all subdomains at any depth automatically (suffix-based matching)
- [ ] Wildcard (*) not needed

### 12. Managed Rule Group Versions

Scripted. Unpinned groups follow the AWS default version, and default changes are announced only through each group's SNS topic.
- [ ] Bot Control unpinned (default Version_1.0) or pinned below 5.0 → Medium. 2.0/3.0 added the `TGT_TokenReuse*` rules; 4.0 Web Bot Authentication; 5.0 400+ bots and a precedence change; 6.x more signatures
- [ ] Other unpinned groups → Low. SQLi has two lineages: 2.0 (JSON parsing in `SQLi_BODY`) and 1.3 → 2.3 → 2.4 → 2.5
- IP reputation and anonymous IP lists are unversioned

### 13. Logging and Monitoring

Read `web_acl.logging.status` in waf-summary.json. `disabled` → logging is confirmed off. `unknown` → config wasn't supplied, remind user to verify. `enabled` → no finding.

### 14. Hashed or Opaque search_string

For byte_match rules with hash/random-token search_string:
- [ ] Evaluate rule normally first (Allow audit, forgeability, etc.)
- [ ] Emit Awareness: value may be shared secret or redacted. Warn about leakage risk.
- [ ] Especially warn if action is Allow — leaked secret = full WAF bypass

### 15. Default Action

- [ ] default_action Allow or Block? CustomRequestHandling is normal.
- [ ] Redundant trailing Allow-all rule: if default is Allow and last rule is Allow-all → recommend removing

### 16. Always-on Challenge for Landing Pages

- [ ] Is there an always-on Challenge targeting landing page URIs? (read crawler-seo.md for implementation)
- [ ] Bot Control at TARGETED with `TGT_TokenAbsent` overridden to Challenge also works as an always-on Challenge, but only for requests inside Bot Control's scope-down. Scripts hand this case to you: check whether that scope covers the landing pages, and whether the labels it relies on can be forged
- [ ] If absent + DDoS protection objectives → Medium severity. Recommend two-rule pattern: Count+Label on landing page URIs → Challenge on label (exclude crawlers)
- [ ] Token immunity time ≥ 4 hours (14400s)?
- [ ] Crawler labeling rule placed before Challenge rule?

---

## Phase 2: Global Cross-checks

### 17. Cross-rule and Label Dependency Analysis

**17a. Label source verification:**
- [ ] Token labels (`token:absent/accepted/rejected`) = shared, produced by Bot Control, ATP, ACFP, AND AntiDDoS AMR
- [ ] `challengeable-request` = produced by AntiDDoS AMR
- [ ] Custom Count rules without labels → Awareness (metric-only or missing labels?)

**17b. Fix impact analysis:**
- [ ] For each fix: trace affected traffic through full rule chain
- [ ] Does fix A break rule B? Remove a label? Prevent downstream rules from working?
- [ ] Document recommended fix order and simultaneous changes needed

### 18. Rule Priority Ordering

Scripted. Report only orderings with real consequences among existing rules:
- [ ] A rule matches a label that only later rules produce
- [ ] An IP block list runs after Allow rules
- [ ] Default-Block ACL: content inspection rule groups run after Allow rules
- [ ] Bot Control runs before rules that block on their own (cost only, Low)

Missing rule types are recommended protections, not ordering problems. Use the recommended order in managed-overrides.md (Appendix D) only to say where a new rule belongs. Don't flag an intentional order, such as `block-internal-url` before an office allow list.

---

## Additional Checks

### 19. Custom Rule Matching Correctness

Scripted.
- [ ] Path Block rules without `URL_DECODE`: WAF inspects the raw path, so `/%69nternal/` bypasses `/internal/`. Recommend `URL_DECODE` ×2 → `REMOVE_NULLS` → `NORMALIZE_PATH` → `LOWERCASE`
- [ ] Literal `*` in a byte match (no wildcard support)
- [ ] Query-string pattern on `UriPath` (`?`, `[?&]`): never matches
- [ ] `UriFragment` with `FallbackBehavior: MATCH`: always true, so an AND with it reduces to its other conditions

Managed rules inspect content as plain text (except the SQLi 2.0 lineage's JSON parsing). Encoded payloads can't all be caught by custom rules either: say so, and point to identity-based controls (IP allow lists, API key checks, tokens) and application input validation.

### 20. Protections Left in Count

Scripted.
- [ ] Whole managed rule groups in Count
- [ ] Content rules inside CRS, KnownBadInputs, SQLi, OS, PHP, WordPress, or AdminProtection overridden to Count (except `SizeRestrictions_BODY`)

### 21. PCI DSS

LLM. PCI DSS covers anyone who stores, processes, or transmits card data, including merchants that take card payments, not only financial companies. Decide scope first:
- The user says the customer takes card payments or is a payment or financial business → in scope
- Otherwise, `llm_context.payment_indicators` lists hosts or paths that look like payment endpoints → ask the user whether these systems are in PCI scope. Until they answer, write the findings with ` ⏳`
- Neither → skip this section
- [ ] ASV scans (Requirement 11.3.2, quarterly by an ASV; 11.3.2.1 after significant change) must not be interfered with by protections that change behavior based on traffic: rate limits, auto-block IP sets, behavior-based bot rules, Challenge (ASV Program Guide v4.0 r2 section 5.6). Consistent signature and path blocking typically doesn't count. An unresolved interference makes the scan inconclusive and then failed (section 7.6)
- [ ] Recommend exceptions for the ASV's IPs on the dynamic mechanisms only, not an Allow rule at the top of the ACL
- [ ] Requirement 6.4.2: the WAF must block attacks, or alert with immediate investigation, and keep audit logs. Long-term Count rules without alerting, and unknown logging, are worth confirming with the QSA
