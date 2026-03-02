# WAF Rules Review Checklist

Evaluate each item. Not all items apply to every Web ACL — skip items irrelevant to the stated purpose.

## 1. Allow Rules Audit

For every rule with `Allow` action:

- [ ] Is the matching condition forgeable? (User-Agent, cookie, header values are all forgeable)
- [ ] Does it use at least one unforgeable verification dimension? (IP set, WAF token, HMAC signature, ASN match)
- [ ] Allow is a terminating action — does bypassing all subsequent rules create a security gap?
- [ ] For managed rule group overrides set to Allow: does the default behavior already handle the intended case? (e.g., Bot Control verified bots are already not blocked by default)

**Common anti-pattern**: Allowing requests based solely on User-Agent prefix for native apps. This lets attackers bypass all WAF rules by forging the UA.

## 2. Scope-down Statements

For every managed rule group with a scope-down:

- [ ] Does the scope-down accidentally make the rule group ineffective? (e.g., `URI EXACTLY "/"` means only the homepage is checked)
- [ ] Is the scope-down too broad, exempting paths that should be protected?
- [ ] For regex-based scope-downs: check anchoring (`^`, `$`) — unanchored patterns are `contains` matches

**Common anti-pattern**: Scope-down with `URI EXACTLY "/"` on IP reputation or anonymous IP rule groups, making them check only homepage requests.

## 3. AntiDDoS AMR Configuration

- [ ] Is `ChallengeAllDuringEvent` enabled (not overridden to Count)?
- [ ] If disabled, is there a valid reason? (native app traffic, non-browser clients)
- [ ] If disabled for native app reasons, recommend dual AMR instance approach:
  - Instance 1: browser traffic, Challenge enabled, Block LOW
  - Instance 2: native app traffic (scope-down by label), Challenge disabled, Block MEDIUM
- [ ] Are exempt URI regexes properly anchored? (`^` for starts-with on API paths, `$` for ends-with on file extensions)
- [ ] Does the exempt regex cover all API paths that can't handle Challenge?
- [ ] Check regex `|` operator precedence: `$` only anchors the last branch unless grouped with `()`
- [ ] **SEO impact**: Does the AntiDDoS AMR scope-down exclude legitimate search engine crawlers? ChallengeAllDuringEvent will Challenge all challengeable requests during a DDoS event. Search engine crawlers (Googlebot, Bingbot, etc.) cannot complete JavaScript Challenge — they may index the Challenge interstitial page instead of actual content, severely damaging SEO. Solution: add a scope-down using ASN + User-Agent double verification to exclude verified crawlers from AntiDDoS inspection. See waf-knowledge.md "Search Engine Crawler Exclusion Pattern" for implementation details.

**Key facts**:
- AntiDDoS AMR detection is per-client-IP, not aggregate. Highly distributed low-rate attacks are harder to detect.
- Detection and mitigation time: "single digit seconds" per official documentation.
- DDoS traffic detected by AntiDDoS AMR is not charged.
- `challengeable-request` label is produced by AntiDDoS AMR (based on GET method + URI not matching exempt regex). Native apps sending GET requests can also get this label.

## 4. Challenge Action Applicability

For every rule using Challenge or CAPTCHA action:

- [ ] Does the rule target requests that can actually complete a Challenge? (Only GET `text/html` requests from browsers)
- [ ] POST requests, API calls, native app requests, CORS preflight OPTIONS — none can complete Challenge
- [ ] For API/POST paths: Challenge effectively equals Block. Is this the intended behavior?
- [ ] If Challenge is used on rate-limit rules for API paths: legitimate users normally won't exceed the threshold, so impact is low — severity should be adjusted accordingly

**Key facts**:
- Challenge returns HTTP 202 with JavaScript interstitial
- Only works when `Accept` header contains `text/html` and client can execute JavaScript
- If client already has valid unexpired WAF token, Challenge acts like Count (no interstitial)

## 5. Bot Control Configuration

- [ ] Are any Common Bot Control rules overridden to Allow? Check if the default behavior already handles the case (verified bots are not matched by default — Allow override also allows unverified/forged bots)
- [ ] `CategorySearchEngine` and `CategorySeo` default action is Block for unverified bots only. Override to Allow lets forged search engine bots through.
- [ ] For SEO protection: use ASN match + UA double verification instead of Bot Control Allow override. This is especially important when AntiDDoS AMR is present — Bot Control Allow overrides don't prevent AntiDDoS ChallengeAllDuringEvent from challenging crawlers. The correct approach is to scope-down AntiDDoS AMR itself to exclude verified crawlers. See waf-knowledge.md "Search Engine Crawler Exclusion Pattern". Reference: https://aws.amazon.com/cn/blogs/china/aws-waf-guide-10-using-amazon-q-developer-cli-to-solve-conflicts-between-ddos-protection-and-seo/
- [ ] `HostingProviderIPList` in AnonymousIpList: Allow override lets cloud-hosted attack traffic bypass all rules
- [ ] If native app bypass rule (Allow by UA) is being fixed → native app requests will enter Bot Control. `SignalNonBrowserUserAgent` (default Block) and Targeted rules (`TGT_TokenAbsent` etc.) will block native apps. Solutions:
  - Best: integrate AWS WAF Mobile SDK
  - Alternative: scope-down Bot Control to exclude native app label, but must use unforgeable condition + rate limiting as fallback

## 6. Token and Label Dependencies

- [ ] Token status labels (`token:absent`, `token:accepted`, etc.) are ONLY produced by Bot Control, ATP, or ACFP rule groups — not by AntiDDoS AMR or other rules
- [ ] `challengeable-request` label IS produced by AntiDDoS AMR
- [ ] AntiDDoS suspicion labels (`high/medium/low-suspicion-ddos-request`) and `event-detected` label are produced by AntiDDoS AMR
- [ ] Custom labels from earlier rules can be used in later rules' scope-down or conditions
- [ ] Check label dependency chains: if rule A's fix depends on rule B's label, note the dependency

## 7. Rate-based Rules

- [ ] Rate-based rules do not take effect instantaneously — there is a delay from threshold breach to activation
- [ ] Action is Challenge on API paths? Effectively equals Block (low severity if users won't exceed threshold)
- [ ] Are rate limits reasonable for the endpoint? (payment APIs should have lower limits than static pages)
- [ ] Is there rate limiting coverage for native app traffic that bypasses Challenge-based protections?

## 8. IP Reputation and Anonymous IP Rules

- [ ] Are these rule groups actually inspecting all traffic? (Check scope-down)
- [ ] `HostingProviderIPList` action: Allow is dangerous for DDoS protection (attackers use cloud VMs)
- [ ] Rule action overrides: Challenge is better than Allow for reputation-flagged IPs
- [ ] If scope-down is too narrow, these expensive rule groups provide no value

## 9. Cross-rule Dependency Analysis

After identifying all issues, use the rule execution flow (built in workflow step 3) to check for fix dependencies:

- [ ] For each proposed fix, trace the affected traffic through the full rule chain. Does the fix change which subsequent rules the traffic reaches?
- [ ] Does fixing rule A cause rule B to break? (e.g., removing an Allow bypass exposes traffic to downstream rules that weren't designed for it)
- [ ] Does fixing rule A remove a label that rule B depends on?
- [ ] If a Count rule is changed to Block, does it prevent labels from being added that downstream rules need?
- [ ] Are there circular dependencies?
- [ ] Document the recommended fix order
- [ ] For each fix, list what else must change simultaneously

## 10. Dual AMR Instance Pattern

When different traffic types (browser vs native app) need different mitigation strategies:

- [ ] Use label-based scope-down to split traffic
- [ ] Configure each AMR instance with appropriate Challenge/Block settings
- [ ] Implementation: copy AMR JSON config → create custom rule → change rule name and metric name → save

## 11. Landing Page and Cookie-based Logic

- [ ] Are business cookies used for security decisions? (cookies are forgeable)
- [ ] Better alternative: use `Accept: text/html` + `GET` method to identify landing page requests (browser navigation)
- [ ] Use always-on Challenge on landing pages + extended token immunity time (e.g., 4 hours) to replace cookie-based old/new user detection
- [ ] WAF token is unforgeable and serves as proof of prior Challenge completion
- [ ] Search engine crawlers send `GET` + `Accept: text/html` — exclude with ASN match if Challenge is applied to landing pages

## 12. Rule Priority Ordering

- [ ] Is AntiDDoS AMR at or near the highest priority? It should inspect as much traffic as possible for accurate baseline and detection. However, labeling rules that AntiDDoS AMR depends on (e.g., native app identification for dual-AMR scope-down) must be placed before it.
- [ ] Are Allow rules (IP whitelist, probe service) placed before managed rule groups?
- [ ] Are Count+Label rules placed before the rules that consume their labels? (A label-consuming rule placed before its label-producing rule will never see the label)
- [ ] Are rate-based rules placed appropriately relative to managed rule groups?
- [ ] Could a higher-priority Allow rule cause traffic to skip critical lower-priority protections?

## 13. Missing Baseline Protections

- [ ] Is AWSManagedRulesCommonRuleSet (CRS) present? (OWASP Top 10 protection). If recommending CRS, always advise overriding `SizeRestrictions_Body` to Count — this rule blocks request bodies larger than 8KB and frequently causes false positives on file upload endpoints, API endpoints with large payloads, etc. Most users don't know which of their endpoints need large bodies.
- [ ] Is AWSManagedRulesKnownBadInputsRuleSet present? (Log4j, Java deserialization, etc.)
- [ ] Are application-specific rule groups present if applicable? (SQLi, PHP, Linux, WordPress, etc.)
- [ ] Is the absence of baseline rule groups intentional? (e.g., Web ACL is DDoS-only by design)

## 14. WCU Awareness

Note: WCU cannot be accurately calculated from JSON alone. When recommending adding new rules or rule groups, remind the user to verify that the Web ACL will not exceed the 5000 WCU limit after applying changes.

## 15. Token Domain Configuration

- [ ] Does `token_domains` include the apex domain? (e.g., `example.com` automatically covers `www.example.com`, `sub.example.com` and all subdomains — no need to list each subdomain separately)
- [ ] Wildcard (`*`) is NOT needed and should not be used
- [ ] Are there 4th-level domains (e.g., `a.b.example.com`) that need separate entries? Apex domain only covers up to 3rd-level subdomains.

## 16. Managed Rule Group Versions

Note: If any managed rule groups are locked to a specific static version, remind the user to check whether a newer recommended version is available in the AWS console.

## 17. Logging and Monitoring

Note: If the Web ACL JSON does not show WAF logging configuration (CloudWatch Logs, S3, or Kinesis), remind the user that without logging, issues cannot be diagnosed and false positives cannot be identified.

## 18. Hashed or Opaque search_string in byte_match_statement

Some `byte_match_statement` rules contain a `search_string` that includes a hash or random token component. The hash may be the entire value (e.g., `9f86d081884c7d65`) or appended to a readable prefix (e.g., `my-app-9f86d081884c7d65`). This can happen for two reasons:
- The internal system redacted the customer's real value and replaced it with a hash for privacy
- The customer intentionally configured a hash/token as a shared secret

In either case, the reviewer cannot know the actual value or its secrecy level.

**Workflow:**

1. First, evaluate the rule normally using all other checklist items (Allow audit, scope-down, forgeability, etc.)
2. Then, for every `byte_match_statement` whose `search_string` contains what appears to be a hash or random token segment (not entirely composed of standard header names, URI paths, known constants, or human-readable words), emit an **Awareness** finding with:
   - The rule name and which field is being matched (`single_header`, `single_query_argument`, `body`, etc.)
   - A reminder that the `search_string` may be a shared secret or redacted value
   - Advise the user to assess whether this value could be captured or leaked (e.g., logged in access logs, visible in browser dev tools, transmitted over unencrypted channels)
   - Especially warn if the rule action is **Allow** — a leaked shared secret in an Allow rule lets attackers bypass all downstream WAF protections

## 19. Default Action

- [ ] What is the Web ACL's `default_action`? (Allow or Block) This determines what happens to requests that don't match any rule.
- [ ] If `default_action` is Allow: all requests that survive every rule are allowed. Ensure the rule set is comprehensive enough that only legitimate traffic falls through.
- [ ] If `default_action` is Block: only explicitly allowed traffic passes. This is stricter but may cause false positives if Allow rules are incomplete.
- [ ] **Redundant trailing Allow-all rule**: If `default_action` is already Allow, check whether the last rule in the Web ACL is a custom rule that matches all requests with Allow action. This is redundant — it wastes WCU and can cause maintenance confusion (e.g., a future maintainer may insert new rules after it, not realizing they will never be evaluated). Recommend removing it.

## 20. Always-on Challenge for HTML Pages

For Web ACLs with DDoS protection objectives:

- [ ] Is there an always-on Challenge rule targeting browser HTML page requests (`GET` + `Accept` contains `text/html`)? This is a highly effective proactive DDoS defense — see waf-knowledge.md "Always-on Challenge for HTML Pages" for rationale.
- [ ] If present, is the token immunity time extended to at least 4 hours (14400 seconds)? Default 300 seconds works but may cause unnecessary re-challenges for real users.
- [ ] Is the always-on Challenge rule placed AFTER a crawler identification rule (Count+Label with ASN + UA verification)? The Challenge rule must scope-down to exclude requests labeled as legitimate crawlers, otherwise search engine SEO will be impacted.
- [ ] If not present and the Web ACL relies solely on AntiDDoS AMR for DDoS protection, consider recommending always-on Challenge as a complementary proactive layer.
