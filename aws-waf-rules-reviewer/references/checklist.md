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
  - **Step 1 (prerequisite)**: Add a Count+Label rule **before** both AMR instances to identify and label native app traffic (e.g., label `native-app:identified`). This rule must be at a higher priority (lower number) than both AMR instances, because the AMR scope-downs consume this label — it must already exist when AMR evaluates the request.
  - **Step 2**: Configure two AMR instances:
    - Instance 1 (browser traffic): scope-down to exclude the native app label, `ChallengeAllDuringEvent` enabled, Block LOW (LOW is the default; browser traffic already has `ChallengeAllDuringEvent` as the primary mitigation, so Block sensitivity can stay at default)
    - Instance 2 (native app traffic): scope-down to match the native app label only, `ChallengeAllDuringEvent` disabled, Block MEDIUM (since Challenge is disabled for native apps, Block is the only available mitigation — raise sensitivity from default LOW to MEDIUM for adequate protection)
  - **How to configure two AMR instances**: The AWS console does not allow adding the same managed rule group twice. To duplicate it: in the Web ACL JSON editor, copy the existing AMR rule entry, paste it as a new custom rule, then change the `Name` and `MetricName` fields to unique values. Save — AWS WAF will treat them as two independent rule instances with separate configurations.
- [ ] Are exempt URI regexes properly anchored? (`^` for starts-with on API paths, `$` for ends-with on file extensions). Unanchored API path patterns are `contains` matches — an attacker can exploit this by targeting paths that incidentally contain the exempt keyword (e.g., `/admin/api/delete` or `/internal/messages/export` would be exempted by unanchored `\/api\/` or `\/messages` patterns), causing attack requests to bypass ChallengeAllDuringEvent.
- [ ] Does the exempt regex cover all API paths that can't handle Challenge?
- [ ] Check regex `|` operator precedence: `$` only anchors the last branch unless grouped with `()`
- [ ] **SEO impact**: Does the Web ACL have a crawler labeling rule before AntiDDoS AMR? `ChallengeAllDuringEvent` will Challenge all challengeable requests during a DDoS event. Search engine crawlers (Googlebot, Bingbot, etc.) may not reliably complete JavaScript Challenge — real-world cases have been observed where crawlers indexed the Challenge interstitial page instead of actual content, severely damaging SEO. The correct solution is a two-step approach: (1) add a Count+Label rule before AntiDDoS AMR that identifies verified crawlers via ASN + User-Agent double verification and labels them (e.g., `crawler:verified`); (2) add a scope-down to AntiDDoS AMR that excludes requests with that label. See waf-knowledge.md "ASN + UA Crawler Labeling Rule" and "Search Engine Crawler Exclusion Pattern" for implementation details and JSON examples.

**Key facts**:
- AntiDDoS AMR detection is per-client-IP, not aggregate. Highly distributed low-rate attacks are harder to detect.
- Detection and mitigation time: "single digit seconds" per official documentation.
- DDoS traffic detected by AntiDDoS AMR is not charged.
- `challengeable-request` label is produced by AntiDDoS AMR (based on GET method + URI not matching exempt regex). Native apps sending GET requests can also get this label.

## 4. Challenge Action Applicability

For every rule using Challenge or CAPTCHA action:

- [ ] Does the rule target requests that can actually complete a Challenge/CAPTCHA? (Only GET `text/html` requests from browsers)
- [ ] POST requests, API calls, native app requests, CORS preflight OPTIONS — none can complete Challenge or CAPTCHA. Both actions return a JS interstitial that requires browser execution; for non-browser or non-GET requests, both are effectively equivalent to Block.
- [ ] For API/POST paths: Challenge or CAPTCHA effectively equals Block. Is this the intended behavior?
- [ ] If Challenge is used on rate-limit rules for API paths: legitimate users normally won't exceed the threshold, so impact is low — severity should be adjusted accordingly

**Key facts**:
- Both Challenge and CAPTCHA return an HTTP interstitial that requires JavaScript execution in a browser
- Neither works for POST requests, API calls, native apps, or non-`text/html` responses — treat both as Block in those contexts
- Challenge: silent JS puzzle, returns HTTP 202
- CAPTCHA: visible image puzzle, returns HTTP 405
- If client already has valid unexpired WAF token, Challenge acts like Count (no interstitial); CAPTCHA always shows the puzzle regardless of token state

## 5. Bot Control Configuration

- [ ] **Common level only — Awareness**: If Bot Control is configured at Common level only (no Targeted), emit an Awareness finding explaining what Common level can and cannot do:
  - **Can do**: identify self-declared bots via User-Agent, verify bots belonging to known organizations via reverse DNS lookup, block unverified/forged bot User-Agents
  - **Cannot do**: detect bots that disguise themselves as normal browsers (no bot-specific User-Agent), detect advanced bots using behavioral analysis, detect credential stuffing or inventory hoarding attacks
  - Common level only protects against bots that openly identify themselves. Any bot using a standard browser User-Agent will pass through Common Bot Control completely undetected. Advise the user to consider deploying Targeted level if they need protection against advanced or disguised bots.
- [ ] Are any Common Bot Control rules overridden to Allow? Category rules only match unverified bots — verified bots already pass without action, and forged UAs never match category rules (they fall through to SignalNonBrowserUserAgent). Allow override on a category rule lets unverified bots in that category bypass all subsequent WAF rules.
- [ ] `CategorySearchEngine` and `CategorySeo` default action is Block for unverified bots only. Override to Allow lets unverified search engine bots (e.g., individual-triggered Google SaaS tools) bypass all subsequent rules. Forged Googlebot UAs are NOT affected — they never match the category rule. Severity: **Low** (limited blast radius; does not enable full WAF bypass for arbitrary attackers). The correct approach for SEO protection is NOT to override these categories to Allow, but to use ASN match + UA double verification via a Count+Label rule that labels verified crawlers (e.g., `crawler:verified`), then scope-down both AntiDDoS AMR and Always-on Challenge to exclude that label. This is especially important when AntiDDoS AMR is present — Bot Control Allow overrides don't prevent AntiDDoS ChallengeAllDuringEvent from challenging crawlers. See waf-knowledge.md "ASN + UA Crawler Labeling Rule" and "Search Engine Crawler Exclusion Pattern". Reference: https://aws.amazon.com/cn/blogs/china/aws-waf-guide-10-using-amazon-q-developer-cli-to-solve-conflicts-between-ddos-protection-and-seo/
- [ ] **SignalNonBrowserUserAgent and CategoryHttpLibrary**: default action is Block, but these rules frequently cause false positives on legitimate non-browser clients (native apps, API clients, legitimate tools). Best practice is to override both to **Count**. This avoids false positives while still adding labels that can be used by downstream rules for further evaluation.
- [ ] **Conditional — only check if Allow Rules Audit (section 1) found a UA-based Allow rule being fixed**: If native app bypass rule (Allow by UA) is being fixed → native app requests will enter Bot Control. Two migration paths:
  - **Short-term**: scope-down Bot Control to exclude native app traffic using an unforgeable label (e.g., a label applied by an earlier Count rule based on a non-UA condition). Since scope-down applies to the entire managed rule group, native app traffic bypasses all of Bot Control — both Common and Targeted levels. Do NOT discuss `SignalNonBrowserUserAgent` or `TGT_TokenAbsent` in this context; they are irrelevant when the entire rule group is bypassed.
  - **Medium-term**: integrate AWS WAF Mobile SDK. The SDK generates valid WAF tokens for native app requests, so Targeted level works correctly (`TGT_TokenAbsent` will not fire). However, Common level still requires attention: `SignalNonBrowserUserAgent` will Block native app requests and must be overridden to **Count** when the scope-down is removed.
  - **NEVER override `TGT_TokenAbsent` to Count** — this rule identifies token-absent requests and is the foundation of all Targeted Bot Control detection. Overriding it to Count disables the entire Targeted level's session-tracking mechanism.

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
- [ ] **Overlapping scope-down across multiple rate-based rules**: If the Web ACL contains multiple rate-based rules, compare their scope-down conditions. If two or more rules have overlapping or containing scope-downs (e.g., one targets `/api/` and another targets all traffic), only the rule with the lowest threshold will ever trigger for the overlapping traffic — the others are effectively redundant for that traffic. Advise the user to adjust scope-downs to make them mutually exclusive if the intent was to apply different rate limits to different traffic types.

## 8. IP Reputation and Anonymous IP Rules

### AWSManagedRulesAmazonIpReputationList (WCU: 25)

This rule group contains three rules:

- `AWSManagedIPReputationList` (default Block): known malicious IPs from Amazon threat intelligence (MadPot). Generally safe to keep at default.
- `AWSManagedReconnaissanceList` (default Block): IPs performing reconnaissance against AWS resources. Generally safe to keep at default.
- `AWSManagedIPDDoSList` (default **Count**): IPs identified as participating in DDoS activities, including open proxies and potentially some residential proxies that are exploited as DDoS relay points. Default is Count because these IPs may belong to legitimate users whose devices were temporarily compromised — blocking them outright would cause false positives.

- [ ] Are these rule groups actually inspecting all traffic? (Check scope-down)
- [ ] If scope-down is too narrow, these rule groups provide no value
- [ ] **AWSManagedIPDDoSList at default Count**: this rule only adds the label `awswaf:managed:aws:amazon-ip-list:AWSManagedIPDDoSList` without taking action. If no downstream rule uses this label, the rule provides no protection. Two options for the user to consider:
  1. Deploy AntiDDoS AMR — it subsumes the ManagedIPDDoSList capability, so this rule is no longer needed when AMR is present
  2. If the user does not want to deploy AntiDDoS AMR: add a rate-based rule downstream that uses the DDoS IP list label as a scope-down condition, applying stricter rate limits to traffic from known DDoS IPs. This avoids false positives (rate limiting instead of outright blocking) while reducing the impact of DDoS traffic from these IPs

### AWSManagedRulesAnonymousIpList (WCU: 50)

- [ ] Rule action overrides: Challenge is better than Allow for reputation-flagged IPs
- [ ] **HostingProviderIPList** (default Block): This rule was designed to block traffic from cloud hosting providers, assuming legitimate users don't originate from cloud platforms. However, this assumption is increasingly outdated — many enterprises route traffic through cloud-based proxies, VPNs, or SaaS gateways, and many websites serve both enterprise and consumer traffic on the same domain without separate Web ACLs. As a result, the default Block action frequently causes false positives.
  - [ ] If HostingProviderIPList is at default Block action: best practice is to override to **Count**. This avoids false positives while still adding the `awswaf:managed:aws:anonymous-ip-list:HostingProviderIPList` label to matching requests.
  - [ ] If overridden to Allow: this is dangerous — it lets cloud-hosted attack traffic bypass all subsequent rules. Override to Count instead.
  - [ ] Awareness: remind the user that the HostingProviderIPList label can be used by downstream rules for rate limiting on hosting-provider traffic, if their business requires it. Do not recommend specific rate limiting configurations — this depends on the user's business context.

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

When different traffic types (browser vs native app) need different mitigation strategies, see section 3 "AntiDDoS AMR Configuration" for the full dual instance setup guide.

## 11. Landing Page and Cookie-based Logic

- [ ] Are business cookies used for security decisions? (cookies are forgeable)
- [ ] Better alternative: use `Accept: text/html` + `GET` method to identify landing page requests (browser navigation)
- [ ] Use always-on Challenge on landing pages + extended token immunity time (e.g., 4 hours) to replace cookie-based old/new user detection
- [ ] WAF token is unforgeable and serves as proof of prior Challenge completion
- [ ] Search engine crawlers send `GET` + `Accept: text/html` — if Challenge is applied to landing pages, exclude verified crawlers using the `crawler:verified` label (requires the ASN + UA crawler labeling rule to be placed before the Challenge rule; see waf-knowledge.md "ASN + UA Crawler Labeling Rule")

## 12. Rule Priority Ordering

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

## 13. Missing Baseline Protections

- [ ] Is AWSManagedRulesCommonRuleSet (CRS) present? (OWASP Top 10 protection). If recommending CRS, always advise overriding `SizeRestrictions_Body` to Count — this rule blocks request bodies larger than 8KB and frequently causes false positives on file upload endpoints, API endpoints with large payloads, etc. Most users don't know which of their endpoints need large bodies.
- [ ] Is AWSManagedRulesKnownBadInputsRuleSet present? (Log4j, Java deserialization, etc.)
- [ ] Are application-specific rule groups present if applicable? (SQLi, PHP, Linux, WordPress, etc.)
- [ ] Is the absence of baseline rule groups intentional? (e.g., Web ACL is DDoS-only by design)

## 14. WCU Awareness

Note: WCU cannot be accurately calculated from JSON alone. When recommending adding new rules or rule groups, remind the user to verify that the Web ACL will not exceed the 5000 WCU limit after applying changes.

## 15. Token Domain Configuration

- [ ] Does `token_domains` include the apex domain? (e.g., `example.com` automatically covers `www.example.com`, `sub.example.com` and all single-level subdomains — no need to list each subdomain separately)
- [ ] Wildcard (`*`) is NOT needed and should not be used
- [ ] Are there multi-level subdomains (e.g., `a.b.example.com`) that need separate entries? The apex domain `example.com` only covers `*.example.com` (one level of subdomain). Deeper subdomains like `a.b.example.com` require a separate `token_domains` entry for `b.example.com`.

## 16. Managed Rule Group Versions

Only check versions for these specific rule groups:
- **AWSManagedRulesSQLiRuleSet**: if pinned to a version below 2.0, recommend upgrading. The current default version is 1.0, but version 2.0 has significantly higher SQLi detection coverage.
- **AWSManagedRulesBotControlRuleSet**: if pinned to a version below 5.0, recommend upgrading. The current default version is 1.0, which is outdated. Version 5.0's Common level can identify close to 700 bot types (up from far fewer in 1.0) based on UA and IP, and Targeted level includes substantially more detection rules.

For all other managed rule groups, do not flag version numbers — the version shown in JSON is just the current snapshot and requires no action. Only SQLiRuleSet and BotControlRuleSet are flagged because their default versions are significantly behind the latest, with meaningful detection capability gaps.

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

- [ ] What is the Web ACL's `default_action`? (Allow or Block) This determines what happens to requests that don't match any rule. Note: `default_action` may also contain `CustomRequestHandling` (e.g., adding custom headers to the response) — this is normal configuration and not a security concern by itself.
- [ ] If `default_action` is Allow: all requests that survive every rule are allowed. Ensure the rule set is comprehensive enough that only legitimate traffic falls through.
- [ ] If `default_action` is Block: only explicitly allowed traffic passes. This is stricter but may cause false positives if Allow rules are incomplete.
- [ ] **Redundant trailing Allow-all rule**: If `default_action` is already Allow, check whether the last rule in the Web ACL is a custom rule that matches all requests with Allow action. This is redundant — it wastes WCU and can cause maintenance confusion (e.g., a future maintainer may insert new rules after it, not realizing they will never be evaluated). Recommend removing it.

## 20. Always-on Challenge for HTML Pages

For Web ACLs with DDoS protection objectives:

- [ ] Is there an always-on Challenge rule targeting browser HTML page requests (`GET` + `Accept` contains `text/html`)? This is the most effective proactive DDoS defense — it takes effect immediately with zero detection delay, unlike AntiDDoS AMR which requires time to establish a baseline. See waf-knowledge.md "Always-on Challenge for HTML Pages" for rationale.
- [ ] If not present and the Web ACL has DDoS protection objectives, flag as **Medium** severity and recommend adding it. Provide the following rule JSON directly in the report for easy copy-paste:

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
- [ ] Is there a crawler labeling rule (Count+Label with ASN + UA verification, e.g., `crawler:verified`) placed **before** the always-on Challenge rule? Without it, search engine crawlers will be continuously challenged on every HTML page request — not just during DDoS events — preventing them from indexing site content entirely. The always-on Challenge rule must exclude requests with the crawler label in its scope-down. See waf-knowledge.md "ASN + UA Crawler Labeling Rule" for the labeling rule JSON.
