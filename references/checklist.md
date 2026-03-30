# WAF Rules Review Checklist

Evaluate each item. Not all items apply to every Web ACL — skip items irrelevant to the stated purpose.

This checklist is organized in two phases:
- **Phase 1 (sections 1–16)**: Independent checks — each section evaluates rules or rule groups in isolation.
- **Phase 2 (sections 17–18)**: Global cross-checks — these require findings from all Phase 1 sections as input.

---

## Phase 1: Independent Checks

### 1. Allow Rules Audit

For every rule with `Allow` action:

- [ ] Is the matching condition forgeable? (User-Agent, cookie, header values are all forgeable)
- [ ] Does it use at least one unforgeable verification dimension? (IP set, WAF token, HMAC signature, ASN match)
- [ ] Allow is a terminating action — does bypassing all subsequent rules create a security gap?
- [ ] For managed rule group overrides set to Allow: does the default behavior already handle the intended case? (e.g., Bot Control verified bots are already not blocked by default)

**Common anti-pattern**: Allowing requests based solely on User-Agent prefix for native apps. This lets attackers bypass all WAF rules by forging the UA.

> **Cross-reference flag**: If a UA-based Allow rule is found (e.g., native app bypass by User-Agent prefix), note `UA_ALLOW_FOUND` — referenced by section 5.

### 2. Scope-down Statements

For every managed rule group with a scope-down:

- [ ] Does the scope-down accidentally make the rule group ineffective? (e.g., `URI EXACTLY "/"` means only the homepage is checked)
- [ ] Is the scope-down too broad, exempting paths that should be protected?
- [ ] For regex-based scope-downs: check anchoring (`^`, `$`) — unanchored patterns are `contains` matches

**Common anti-pattern**: Scope-down with `URI EXACTLY "/"` on IP reputation or anonymous IP rule groups, making them check only homepage requests.

### 3. AntiDDoS AMR Configuration

- [ ] Is `ChallengeAllDuringEvent` enabled (not overridden to Count)?
- [ ] If disabled, is there a valid reason? (native app traffic, non-browser clients)
- [ ] If disabled for native app reasons, recommend dual AMR instance approach. Copy the following implementation details into the report (the user needs step-by-step instructions, not just a summary):
  1. Pre-label native app requests with a Count+Label rule before both AMR instances
  2. AMR instance 1 (browser): scope-down excludes native app label, ChallengeAllDuringEvent enabled, Block LOW
  3. AMR instance 2 (native app): scope-down matches native app label only, ChallengeAllDuringEvent disabled, Block MEDIUM
  4. **How to add two AMR instances**: The AWS console does not allow adding the same managed rule group twice. In the Web ACL JSON editor, copy the existing AMR rule entry, paste it as a new entry, change the `Name` and `MetricName` fields to unique values, then save.
- [ ] Are exempt URI regexes properly anchored? (`^` for starts-with on API paths, `$` for ends-with on file extensions). Unanchored API path patterns are `contains` matches — an attacker can exploit this by targeting paths that incidentally contain the exempt keyword (e.g., `/admin/api/delete` or `/internal/messages/export` would be exempted by unanchored `\/api\/` or `\/messages` patterns), causing attack requests to bypass ChallengeAllDuringEvent.
- [ ] Does the exempt regex cover all API paths that can't handle Challenge?
- [ ] Check regex `|` operator precedence: `$` only anchors the last branch unless grouped with `()`
- [ ] **SEO impact**: Does the Web ACL have a crawler labeling rule before AntiDDoS AMR? `ChallengeAllDuringEvent` will Challenge all challengeable requests during a DDoS event. Search engine crawlers may not reliably complete JavaScript Challenge — real-world cases show crawlers indexing the Challenge interstitial page instead of actual content, severely damaging SEO. See waf-knowledge.md "ASN + UA Crawler Labeling Rule" and "Search Engine Crawler Exclusion Pattern" for the solution (Count+Label rule with ASN+UA double verification, then scope-down AMR to exclude the label). If recommending adding a crawler labeling rule, copy the full rule JSON from waf-knowledge.md "Rule JSON" into the report for easy copy-paste.

**Key facts**: See waf-knowledge.md "AntiDDoS AMR" for detection mechanism, performance, labels produced, and pricing details.

### 4. Challenge Action Applicability

For every rule using Challenge or CAPTCHA action:

- [ ] Does the rule target requests that can actually complete a Challenge/CAPTCHA? (Only GET `text/html` requests from browsers)
- [ ] POST requests, API calls, native app requests, CORS preflight OPTIONS — none can complete Challenge or CAPTCHA. Both actions return a JS interstitial that requires browser execution; for non-browser or non-GET requests, both are effectively equivalent to Block.
- [ ] For API/POST paths: Challenge or CAPTCHA effectively equals Block. Is this the intended behavior?
- [ ] If Challenge is used on rate-limit rules for API paths: legitimate users normally won't exceed the threshold, so impact is low — severity should be adjusted accordingly

#### Count rules with Challenge/Block intent

- [ ] For every Count rule whose name or context suggests the intended action is Challenge or Block (e.g., `challenge_all_traffic`, `block_bad_ips_staging`): evaluate the rule's statement **as if the action were already the intended action**. If the statement would cause unintended impact when switched (e.g., a broad match that would effectively Block all POST/API/native app traffic), flag as **Medium** — the user may not realize the consequences of flipping the action. Include a clear description of what traffic would be affected after the switch.

**Key facts**: See waf-knowledge.md "Challenge Action", "CAPTCHA Action", and "Key difference from Challenge" for full behavior details (HTTP status codes, token-awareness, what can/cannot be challenged).

### 5. Bot Control Configuration

- [ ] **Common level only — Awareness**: If Bot Control is configured at Common level only (no Targeted), emit an Awareness finding explaining what Common level can and cannot do. See waf-knowledge.md "Common level" and "Common level limitations" for the full capability description (verified/unverified/forged UA handling, detection scope, and what it cannot detect).
- [ ] Are any Common Bot Control rules overridden to Allow? Category rules only match unverified bots — verified bots already pass without action, and forged UAs never match category rules (they fall through to SignalNonBrowserUserAgent). Allow override on a category rule lets unverified bots in that category bypass all subsequent WAF rules.
- [ ] `CategorySearchEngine` and `CategorySeo` default action is Block for unverified bots only. Override to Allow lets unverified search engine bots bypass all subsequent rules. Forged Googlebot UAs are NOT affected — they never match the category rule. Severity: **Low** (limited blast radius). The correct approach for SEO protection is the ASN+UA Count+Label crawler labeling rule, not Bot Control Allow overrides. See waf-knowledge.md "Common level common misconfigurations" and "Search Engine Crawler Exclusion Pattern". Reference: https://aws.amazon.com/cn/blogs/china/aws-waf-guide-10-using-amazon-q-developer-cli-to-solve-conflicts-between-ddos-protection-and-seo/
- [ ] **SignalNonBrowserUserAgent and CategoryHttpLibrary**: default action is Block, but these rules frequently cause false positives on legitimate non-browser clients. Best practice is to override both to **Count**. See waf-knowledge.md "Common level common misconfigurations" for rationale.

#### If `UA_ALLOW_FOUND` (from section 1):

- [ ] If native app bypass rule (Allow by UA) is being fixed → native app requests will enter Bot Control. Two migration paths:
  - **Short-term**: scope-down Bot Control to exclude native app traffic using an unforgeable label. Since scope-down applies to the entire managed rule group, native app traffic bypasses all of Bot Control — both Common and Targeted levels. Do NOT discuss `SignalNonBrowserUserAgent` or `TGT_TokenAbsent` in this context; they are irrelevant when the entire rule group is bypassed.
  - **Medium-term**: integrate AWS WAF Mobile SDK. See waf-knowledge.md "Key rules for native app considerations" for details on SDK integration, `SignalNonBrowserUserAgent` override requirements, and `TGT_TokenAbsent` handling.
  - **NEVER override `TGT_TokenAbsent` to Count** — this rule is the foundation of all Targeted Bot Control detection. Overriding it disables the entire session-tracking mechanism.

### 6. Rate-based Rules

- [ ] Rate-based rules do not take effect instantaneously — there is a delay from threshold breach to activation
- [ ] Action is Challenge on API paths? Effectively equals Block (low severity if users won't exceed threshold)
- [ ] Are rate limits reasonable for the endpoint? (payment APIs should have lower limits than static pages)
- [ ] Is there rate limiting coverage for native app traffic that bypasses Challenge-based protections?
- [ ] **Overlapping scope-down across multiple rate-based rules**: If the Web ACL contains multiple rate-based rules, compare their scope-down conditions. If two or more rules have overlapping or containing scope-downs (e.g., one targets `/api/` and another targets all traffic), only the rule with the lowest threshold will ever trigger for the overlapping traffic — the others are effectively redundant for that traffic. Advise the user to adjust scope-downs to make them mutually exclusive if the intent was to apply different rate limits to different traffic types.

### 7. IP Reputation and Anonymous IP Rules

#### AWSManagedRulesAmazonIpReputationList (WCU: 25)

See waf-knowledge.md "AWSManagedRulesAmazonIpReputationList" for rule descriptions and default actions.

- [ ] Are these rule groups actually inspecting all traffic? (Check scope-down)
- [ ] If scope-down is too narrow, these rule groups provide no value
- [ ] **AWSManagedIPDDoSList at default Count**: this rule only adds a label without taking action. If no downstream rule uses this label, the rule provides no protection. See waf-knowledge.md "Relationship with AntiDDoS AMR" for the two options (deploy AntiDDoS AMR which subsumes it, or add a downstream rate-based rule using the label).

#### AWSManagedRulesAnonymousIpList (WCU: 50)

- [ ] Rule action overrides: Challenge is better than Allow for reputation-flagged IPs
- [ ] **HostingProviderIPList** (default Block): This rule's assumption that legitimate users don't originate from cloud platforms is increasingly outdated. See waf-knowledge.md "HostingProviderIPList outdated assumption" for full context.
  - [ ] If at default Block: best practice is to override to **Count**.
  - [ ] If overridden to Allow: dangerous — lets cloud-hosted attack traffic bypass all subsequent rules. Override to Count instead.
  - [ ] Awareness: the HostingProviderIPList label can be used by downstream rules for rate limiting on hosting-provider traffic, if the user's business requires it.

### 8. Landing Page and Cookie-based Logic

- [ ] Are business cookies used for security decisions? (cookies are forgeable)
- [ ] Better alternative: use `Accept: text/html` + `GET` method to identify landing page requests (browser navigation)
- [ ] Use always-on Challenge on landing pages + extended token immunity time (e.g., 4 hours) to replace cookie-based old/new user detection
- [ ] WAF token is unforgeable and serves as proof of prior Challenge completion
- [ ] Search engine crawlers send `GET` + `Accept: text/html` — if Challenge is applied to landing pages, exclude verified crawlers using the `crawler:verified` label (requires the ASN + UA crawler labeling rule to be placed before the Challenge rule; see waf-knowledge.md "ASN + UA Crawler Labeling Rule")

### 9. Missing Baseline Protections

- [ ] Is AWSManagedRulesCommonRuleSet (CRS) present? (OWASP Top 10 protection). If recommending CRS, always advise overriding `SizeRestrictions_Body` to Count — this rule blocks request bodies larger than 8KB and frequently causes false positives on file upload endpoints, API endpoints with large payloads, etc.
- [ ] Is AWSManagedRulesKnownBadInputsRuleSet present? (Log4j, Java deserialization, etc.)
- [ ] Are application-specific rule groups present if applicable? (SQLi, PHP, Linux, WordPress, etc.)
- [ ] Is the absence of baseline rule groups intentional? (e.g., Web ACL is DDoS-only by design)

### 10. WCU Awareness

Note: WCU cannot be accurately calculated from JSON alone. When recommending adding new rules or rule groups, remind the user to verify that the Web ACL will not exceed the 5000 WCU limit after applying changes.

### 11. Token Domain Configuration

- [ ] Does `token_domains` include the apex domain? (e.g., `example.com` automatically covers `www.example.com`, `sub.example.com` and all single-level subdomains — no need to list each subdomain separately)
- [ ] Wildcard (`*`) is NOT needed and should not be used
- [ ] Are there multi-level subdomains (e.g., `a.b.example.com`) that need separate entries? The apex domain `example.com` only covers `*.example.com` (one level of subdomain). Deeper subdomains like `a.b.example.com` require a separate `token_domains` entry for `b.example.com`.

### 12. Managed Rule Group Versions

Only check versions for these specific rule groups:
- **AWSManagedRulesSQLiRuleSet**: if pinned to a version below 2.0, recommend upgrading. The current default version is 1.0, but version 2.0 has significantly higher SQLi detection coverage.
- **AWSManagedRulesBotControlRuleSet**: if pinned to a version below 5.0, recommend upgrading. The current default version is 1.0, which is outdated. Version 5.0's Common level can identify close to 700 bot types (up from far fewer in 1.0) based on UA and IP, and Targeted level includes substantially more detection rules.

For all other managed rule groups, do not flag version numbers — the version shown in JSON is just the current snapshot and requires no action.

### 13. Logging and Monitoring

Note: If the Web ACL JSON does not show WAF logging configuration (CloudWatch Logs, S3, or Kinesis), remind the user that without logging, issues cannot be diagnosed and false positives cannot be identified.

### 14. Hashed or Opaque search_string in byte_match_statement

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

### 15. Default Action

- [ ] What is the Web ACL's `default_action`? (Allow or Block) This determines what happens to requests that don't match any rule. Note: `default_action` may also contain `CustomRequestHandling` (e.g., adding custom headers to the response) — this is normal configuration and not a security concern by itself.
- [ ] If `default_action` is Allow: all requests that survive every rule are allowed. Ensure the rule set is comprehensive enough that only legitimate traffic falls through.
- [ ] If `default_action` is Block: only explicitly allowed traffic passes. This is stricter but may cause false positives if Allow rules are incomplete.
- [ ] **Redundant trailing Allow-all rule**: If `default_action` is already Allow, check whether the last rule in the Web ACL is a custom rule that matches all requests with Allow action. This is redundant — it wastes WCU and can cause maintenance confusion (e.g., a future maintainer may insert new rules after it, not realizing they will never be evaluated). Recommend removing it.

### 16. Always-on Challenge for HTML Pages

For Web ACLs with DDoS protection objectives:

- [ ] Is there an always-on Challenge rule targeting browser HTML page requests (`GET` + `Accept` contains `text/html`)? This is the most effective proactive DDoS defense — it takes effect immediately with zero detection delay, unlike AntiDDoS AMR which requires time to establish a baseline. See waf-knowledge.md "Always-on Challenge for HTML Pages" for rationale.
- [ ] If not present and the Web ACL has DDoS protection objectives, flag as **Medium** severity and recommend adding it. Copy the following rule JSON directly into the report (do NOT just reference this checklist — the user needs the JSON in the report itself):

```json
{
  "Name": "always-on-challenge-html",
  "Priority": 8,
  "Action": { "Challenge": {} },
  "ChallengeConfig": {
    "ImmunityTimeProperty": {
      "ImmunityTime": 14400
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "always-on-challenge-html"
  },
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "ByteMatchStatement": {
            "FieldToMatch": { "Method": {} },
            "PositionalConstraint": "EXACTLY",
            "SearchString": "GET",
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }]
          }
        },
        {
          "ByteMatchStatement": {
            "FieldToMatch": {
              "SingleHeader": { "Name": "accept" }
            },
            "PositionalConstraint": "CONTAINS",
            "SearchString": "text/html",
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }]
          }
        },
        {
          "NotStatement": {
            "Statement": {
              "LabelMatchStatement": {
                "Scope": "LABEL",
                "Key": "crawler:verified"
              }
            }
          }
        }
      ]
    }
  }
}
```

Note: The `NotStatement` above assumes a crawler identification rule (Count+Label) is placed before this rule, labeling verified crawlers with `crawler:verified`. Replace the label key to match whatever label your crawler identification rule produces. If no crawler identification rule exists, add one first (see waf-knowledge.md "ASN + UA Crawler Labeling Rule").

- [ ] If present, is the token immunity time extended to at least 4 hours (14400 seconds)? Default 300 seconds works but may cause unnecessary re-challenges for real users.
- [ ] Is there a crawler labeling rule (Count+Label with ASN + UA verification, e.g., `crawler:verified`) placed **before** the always-on Challenge rule? Without it, search engine crawlers will be continuously challenged on every HTML page request — not just during DDoS events — preventing them from indexing site content entirely. See waf-knowledge.md "ASN + UA Crawler Labeling Rule" for the labeling rule JSON.

---

## Phase 2: Global Cross-checks

These sections require findings from all Phase 1 sections as input. Run them after completing Phase 1.

### 17. Cross-rule and Label Dependency Analysis

#### 17a. Label source verification

- [ ] Token status labels (`token:absent`, `token:accepted`, etc.) are shared labels (`awswaf:managed:token:*`) produced by all intelligent threat mitigation rule groups: Bot Control, ATP, ACFP, and AntiDDoS AMR
- [ ] `challengeable-request` label IS produced by AntiDDoS AMR
- [ ] AntiDDoS suspicion labels (`high/medium/low-suspicion-ddos-request`) and `event-detected` label are produced by AntiDDoS AMR
- [ ] Custom labels from earlier rules can be used in later rules' scope-down or conditions
- [ ] Check label dependency chains: if rule A's fix depends on rule B's label, note the dependency
- [ ] **Custom Count rules without labels**: For every custom rule (not AWS managed, not marketplace managed) with Count action, check whether `RuleLabels` is present and non-empty. If a Count rule produces no label, downstream rules have no way to act on its match result — the rule only contributes a CloudWatch metric. Flag as **Awareness** and ask the user to confirm intent: if the rule is purely for monitoring (metric only), it is valid; if the user intended "label then act", they need to add a `RuleLabels` entry.

#### 17b. Fix impact analysis

After identifying all issues from Phase 1, use the rule execution flow (built in workflow step 3) to check for fix dependencies:

- [ ] For each proposed fix, trace the affected traffic through the full rule chain. Does the fix change which subsequent rules the traffic reaches?
- [ ] Does fixing rule A cause rule B to break? (e.g., removing an Allow bypass exposes traffic to downstream rules that weren't designed for it)
- [ ] Does fixing rule A remove a label that rule B depends on?
- [ ] If a Count rule is changed to Block, does it prevent labels from being added that downstream rules need?
- [ ] Are there circular dependencies?
- [ ] Document the recommended fix order
- [ ] For each fix, list what else must change simultaneously

### 18. Rule Priority Ordering

Compare the Web ACL's rule ordering against the recommended order in waf-knowledge.md "Recommended Rule Priority Order".

- [ ] Are IP whitelist (Allow) and blacklist (Block) rules placed before AntiDDoS AMR?
- [ ] Are Count+Label rules (traffic tagging) placed before all rules that consume their labels?
- [ ] Is AntiDDoS AMR placed as early as possible (after its label dependencies) so it sees full traffic for accurate baseline?
- [ ] Are IP reputation and Anonymous IP rule groups placed after AntiDDoS AMR?
- [ ] Are rate-based rules placed before Always-on Challenge?
- [ ] Is Always-on Challenge placed after IP reputation, Anonymous IP, and rate-based rules to minimize Challenge costs?
- [ ] Are custom rules placed before application layer rule groups (CRS, KnownBadInputs, etc.)?
- [ ] Are Bot Control, ATP (Account Takeover Prevention), and ACFP (Account Creation Fraud Prevention) — if present — placed last to minimize per-request costs? All three use per-request pricing and should be placed after cheaper rules.
- [ ] Could a higher-priority Allow rule cause traffic to skip critical lower-priority protections?
