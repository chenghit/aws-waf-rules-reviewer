# AWS WAF Technical Knowledge Base

## Challenge Action

### How it works
- Returns HTTP 202 with JavaScript interstitial page
- Client browser silently executes the script for environment detection
- On success, client gets/updates `aws-waf-token` cookie, then auto-resubmits original request
- If client already has valid unexpired token, Challenge acts like Count (no interstitial)

### What can be challenged
- Browser `GET` requests with `Accept: text/html` over HTTPS

### What cannot be challenged
- `POST` requests
- CORS preflight `OPTIONS` requests
- Any non-`GET` request
- Non-HTTPS requests
- Non-browser clients (API calls, native apps, CLI tools)
- Requests not accepting HTML (CSS, images, JSON API)
- Small iFrames that accept HTML but can't process interstitial

### Token immunity time
- Default: 300 seconds
- Configurable at Web ACL or rule level
- After successful Challenge, client is not re-challenged until token expires

### WAF token properties
- The `aws-waf-token` cookie is cryptographically signed by AWS — it is **unforgeable**. Attackers cannot craft a valid token without completing the Challenge.
- A valid token serves as proof that the client previously completed a Challenge (or CAPTCHA) successfully.
- This makes WAF token a reliable replacement for business cookies in security decisions. For example, always-on Challenge on landing pages + extended token immunity time (e.g., 4 hours) can replace cookie-based "new vs returning user" detection — the token proves the user has been verified, without relying on forgeable cookies.

## CAPTCHA Action

### How it works
- Returns HTTP 405 with a visible image puzzle interstitial
- User must solve the puzzle; on success, client gets/updates `aws-waf-token` cookie
- If client already has valid unexpired WAF token with a valid CAPTCHA timestamp, CAPTCHA acts like Count (no puzzle shown) — same token-validation logic as Challenge

### What can complete CAPTCHA
- Same constraints as Challenge: browser `GET` requests with `Accept: text/html` over HTTPS

### What cannot complete CAPTCHA
- Same as Challenge: `POST` requests, API calls, native apps, non-`GET` requests, non-browser clients
- **For POST/API paths, CAPTCHA is effectively equivalent to Block** — the interstitial cannot be completed, so the original request is never resubmitted

### Key difference from Challenge
- Challenge: silent JS puzzle, returns HTTP 202. Checks challenge solve timestamp in token.
- CAPTCHA: visible image puzzle, returns HTTP 405. Checks CAPTCHA solve timestamp in token.
- Both are token-aware: if client has valid unexpired token (with the relevant timestamp), both act like Count (no interstitial). Each checks its own timestamp with its own immunity time.
- Both require browser JS execution; neither works for non-browser or non-GET requests

## AntiDDoS AMR (AWSManagedRulesAntiDDoSRuleSet)

### Detection mechanism
- Per-client-IP behavior analysis (NOT aggregate traffic volume)
- Establishes traffic baseline within 15 minutes of activation
- Compares current traffic to baseline, assigns suspicion scores (low/medium/high)
- Distinguishes DDoS from flash crowds (legitimate traffic spikes)

### Performance
- Detection and mitigation: "single digit seconds" per official documentation
- Highly distributed low-rate attacks (many IPs, each sending minimal traffic) are harder to detect because per-IP anomaly may not be significant enough

### Key rules
- `ChallengeAllDuringEvent`: Challenge all challengeable requests during DDoS event (soft mitigation)
- `ChallengeDDoSRequests`: Challenge requests from suspicious sources
- `DDoSRequests`: Block requests from suspicious sources (hard mitigation)

### Sensitivity levels
- Block sensitivity (LOW/MEDIUM/HIGH): controls which suspicion levels trigger Block
  - LOW: only high-suspicion → Block
  - MEDIUM: medium + high → Block
  - HIGH: all suspicion levels → Block
- Challenge sensitivity: same logic for Challenge action

### Labels produced
- `awswaf:managed:aws:anti-ddos:challengeable-request` — GET + URI not matching exempt regex. Note: native apps sending GET requests also receive this label, even though they cannot complete Challenge.
- `awswaf:managed:aws:anti-ddos:event-detected` — DDoS event detected, applied to ALL requests
- `awswaf:managed:aws:anti-ddos:ddos-request` — request from suspicious source
- `awswaf:managed:aws:anti-ddos:high/medium/low-suspicion-ddos-request` — suspicion level

### Exempt URI regex
- Defines URIs that can't handle Challenge (API paths, static assets)
- Regex `|` branches are independent: `$` only anchors the last branch
- API paths without `^` are `contains` matches, not `starts-with` — an attacker can exploit this by targeting paths that incidentally contain the exempt keyword (e.g., `/admin/api/delete` or `/internal/messages/export` would be exempted by unanchored `\/api\/` or `\/messages` patterns), causing attack requests to bypass ChallengeAllDuringEvent
- Always anchor API path branches with `^`: `^\/api\/|^\/query|^\/messages|\.(css|js|png)$`

### Pricing
- $20/month per AMR instance + $0.15/million requests
- DDoS traffic detected and mitigated is NOT charged

### Dual instance pattern
When browser and native app traffic need different strategies:
1. **Pre-label native app requests**: Add a Count+Label rule **before** both AMR instances to label native app traffic (e.g., `native-app:identified`). This rule must be at a higher priority (lower number) than both AMR instances — the label must already exist when AMR evaluates the request.
2. AMR instance 1 (browser traffic): scope-down to exclude the native app label, `ChallengeAllDuringEvent` enabled, Block LOW (LOW is the default; browser traffic already has `ChallengeAllDuringEvent` as the primary mitigation, so Block sensitivity can stay at default)
3. AMR instance 2 (native app traffic): scope-down to match the native app label only, `ChallengeAllDuringEvent` disabled, Block MEDIUM (since Challenge is disabled for native apps, Block is the only available mitigation — raise sensitivity from default LOW to MEDIUM for adequate protection)

Implementation: The AWS console does not allow adding the same managed rule group twice. In the Web ACL JSON editor, copy the existing AMR rule entry, paste it as a new custom rule, change the `Name` and `MetricName` fields to unique values, then save. AWS WAF treats them as two independent rule instances.

### SEO: excluding search engine crawlers from AntiDDoS AMR
`ChallengeAllDuringEvent` will Challenge all challengeable requests during a DDoS event, including search engine crawlers. Although modern crawlers may support JavaScript execution, real-world cases have been observed where crawlers indexed the Challenge interstitial page (HTTP 202) instead of actual content during DDoS events, severely damaging SEO. The root cause is not fully understood — it may be that crawlers behave differently under high-load conditions, or that the Challenge interstitial is served in a context where the crawler does not retry after token acquisition.

The solution is to place the "ASN + UA Crawler Labeling Rule" (see "ASN + UA Crawler Labeling Rule" section) before AntiDDoS AMR, then add a scope-down to AntiDDoS AMR that excludes requests with the `crawler:verified` label:

```json
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
```

If AntiDDoS AMR already has a scope-down (e.g., for native app exclusion via dual instance pattern), combine them with an `AndStatement`:

```json
{
  "AndStatement": {
    "Statements": [
      {
        "NotStatement": {
          "Statement": {
            "LabelMatchStatement": { "Scope": "LABEL", "Key": "crawler:verified" }
          }
        }
      },
      { "...existing scope-down...": {} }
    ]
  }
}
```

## Bot Control (AWSManagedRulesBotControlRuleSet)

### Common level
- Identifies self-declared bots by analyzing the User-Agent header
- Bots fall into three categories based on how Common level handles them:
  1. **Verified bots** — UA claims to belong to a specific organization (e.g., Googlebot, Bingbot, Route53 Health Check) AND reverse DNS lookup confirms the source IP belongs to that organization. The matching category rule adds labels (`bot:verified` + category + name) but takes **no action**. Bot Control evaluation ends here; the request continues to subsequent Web ACL rules.
  2. **Unverified bots** — UA identifies the bot as belonging to a known category, but the bot cannot be verified via reverse DNS. This includes: bots not belonging to any specific organization (e.g., okhttp, WhatsApp), bots triggered by individual users on personal devices, bots whose business model doesn't involve visiting websites (e.g., scanners, curl), and bots from organizations where individual-triggered requests can't be reverse-DNS-verified (e.g., some Google SaaS developer tools). The matching category rule adds labels (`bot:unverified` + category + name) and applies the **default action (Block)**.
  3. **Unknown non-browser UA** — UA is neither a browser UA nor any recognized bot UA, OR it claims to be an organization bot but reverse DNS verification fails (forged UA). These requests do NOT match any category rule. They fall through to `SignalNonBrowserUserAgent`, which adds `signal:non_browser_user_agent` and applies the **default action (Block)**.
- Can identify close to 700 bot types based on UA and IP (version 5.0+; earlier versions identify significantly fewer)

### Common level limitations
- **Only detects bots that self-identify via User-Agent.** If a bot uses a standard browser User-Agent (e.g., Chrome or Firefox UA), Common level will not detect it at all — the request passes through Bot Control as if it were a normal browser request.
- No behavioral analysis, no browser fingerprinting, no ML-based detection
- Cannot detect: credential stuffing bots, scraping bots using real browser UAs, headless browsers, automated tools that mimic human behavior
- Common level is a UA-based classifier, not a bot defense solution for advanced threats

### Common level common misconfigurations

**Overriding CategorySearchEngine/CategorySeo to Allow to "protect SEO":**
This is unnecessary and potentially harmful, but the actual risk is more nuanced than it appears. Category rules only match **unverified** bots in that category — bots that self-identify as search engine crawlers but cannot be verified via reverse DNS (e.g., individual-triggered Google SaaS tools, personal-device bots). Verified crawlers (e.g., real Googlebot with confirmed reverse DNS) are already handled without any action by the category rule — they pass through with `bot:verified` label regardless of the override. Forged Googlebot UAs (reverse DNS fails) do NOT match `CategorySearchEngine` at all — they fall through to `SignalNonBrowserUserAgent` and are Blocked. Therefore, overriding `CategorySearchEngine` to Allow only affects unverified search engine bots (which would otherwise be Blocked), allowing them to bypass all subsequent WAF rules. Severity: **Low** — the blast radius is limited to unverified bots in that category; it does not enable full WAF bypass for arbitrary attackers. The correct approach: keep default actions. If AntiDDoS AMR's ChallengeAllDuringEvent is a concern for crawlers, use the Count+Label crawler labeling rule to label verified crawlers, then scope-down both AntiDDoS AMR and Always-on Challenge to exclude that label (see "ASN + UA Crawler Labeling Rule" and "Search Engine Crawler Exclusion Pattern"), not Bot Control Allow overrides.

**Keeping SignalNonBrowserUserAgent and CategoryHttpLibrary at default Block:**
These two rules block requests with non-browser User-Agents. Default Block frequently causes false positives on legitimate non-browser clients (native apps, API clients, monitoring tools, legitimate HTTP libraries). Best practice is to override both to **Count**. This preserves the labeling (for downstream rules to use) while avoiding false positives.

### Common level key labels
- `bot:verified` — UA verified via reverse DNS as belonging to a specific organization. The matching category rule takes no action; Bot Control evaluation ends here and the request continues to subsequent Web ACL rules.
- `bot:unverified` — Bot identified as a known category but cannot be verified (no specific organization, personal device, or individual-triggered). The matching category rule applies default action (Block).
- `signal:non_browser_user_agent` — Either: (1) UA claims to be an organization bot but reverse DNS verification failed (forged UA), or (2) UA is neither a browser nor any recognized bot UA. These requests do NOT match any category rule; they fall through to `SignalNonBrowserUserAgent`. Default action: Block.

### Verified vs unverified bots
- For verified bots: the matching category rule adds labels only (`bot:verified` + category + name), takes no action. Bot Control evaluation ends here.
- For unverified bots: the matching category rule adds labels (`bot:unverified` + category + name) and applies default action (Block).
- For forged/unknown UA: no category rule matches; falls through to `SignalNonBrowserUserAgent` (Block).
- Override to Allow on a category rule only affects unverified bots in that category — verified bots already pass without action, and forged UAs never match the category rule.

### Targeted level
- Includes all Common level protections
- Adds behavioral analysis, browser fingerprinting, and ML-based detection for advanced bots
- Has a built-in scope-down that automatically skips requests with `bot:verified` label — verified bots are never challenged by Targeted rules
- Rules prefixed with `TGT_` (e.g., TGT_TokenAbsent, TGT_VolumetricIpTokenAbsent)
- Per-request pricing: $10/million requests (10x more expensive than Common level at $1/million)
- Designed for advanced bot detection (credential stuffing, inventory hoarding), NOT for volumetric DDoS

### Token labels
- `awswaf:managed:token:absent/accepted/rejected` — shared token labels produced by all intelligent threat mitigation rule groups: Bot Control, ATP, ACFP, **and AntiDDoS AMR**
- These are shared labels with namespace `awswaf:managed:token:*`, not specific to any single rule group
- `token:absent` means request has no WAF token

### Key rules for native app considerations

**Short-term: scope-down Bot Control to exclude native app traffic**
- Apply a scope-down to the entire Bot Control managed rule group using an unforgeable label (e.g., a label applied by an earlier Count rule). This bypasses the entire rule group — both Common and Targeted levels — for native app traffic. `SignalNonBrowserUserAgent` and `TGT_TokenAbsent` are irrelevant in this scenario since the rule group is not evaluated at all.

**Medium-term: integrate AWS WAF Mobile SDK**
- The SDK generates valid WAF tokens for native app requests. Remove the scope-down once SDK is integrated.
- Targeted level: works correctly. `TGT_TokenAbsent` will not fire for SDK-enabled requests.
- Common level: `SignalNonBrowserUserAgent` (default Block) will Block native app requests. Must be overridden to **Count** when the scope-down is removed.
- **NEVER override `TGT_TokenAbsent` to Count** — it is the foundation of all Targeted Bot Control detection. Overriding it disables the entire session-tracking mechanism for token-absent requests.

**Key rules**:
- `SignalNonBrowserUserAgent` (default Block): blocks non-browser User-Agents. Override to **Count** when native apps are present and not excluded via scope-down.
- `TGT_TokenAbsent` (default Count, often overridden to Challenge): flags requests without WAF token. **Do not override to Count.**
- `TGT_VolumetricIpTokenAbsent` (default Challenge): 5+ requests from same IP without token in 5 min

## Rate-based Rules

### Characteristics
- There is a delay from threshold breach to rule activation — rate-based rules do not take effect instantaneously
- Evaluation window options: 60s (1 min), 120s (2 min), 300s (5 min, default), 600s (10 min)
- Rate limit threshold: minimum 10 requests per evaluation window, no upper bound specified
- Action: any rule action except Allow

### Challenge action on rate-limit rules
- For API paths: Challenge = Block (clients can't complete)
- For browser paths: legitimate users rarely exceed thresholds
- Low severity issue in DDoS context

### Native app traffic coverage
- Native app traffic that bypasses Challenge-based protections (e.g., via scope-down exclusion or because native apps cannot complete Challenge) still needs rate limiting as a defense layer
- Ensure at least one rate-based rule covers native app traffic paths without relying on Challenge as the action

### Multiple rate-based rules with overlapping scope-downs
- If a Web ACL has multiple rate-based rules, and their scope-down conditions overlap or have a containing relationship (e.g., one targets `/api/` and another targets all traffic), only the rule with the lowest threshold will ever trigger for the overlapping traffic
- The other rules are effectively redundant for that traffic
- If the intent was different rate limits for different traffic types, scope-downs should be adjusted to be mutually exclusive

## IP Reputation Rule Groups

### AWSManagedRulesAmazonIpReputationList (WCU: 25)
Contains three rules:
- `AWSManagedIPReputationList` (default Block): known malicious IPs from Amazon threat intelligence (MadPot). Generally safe to keep at default.
- `AWSManagedReconnaissanceList` (default Block): IPs performing reconnaissance against AWS resources. Generally safe to keep at default.
- `AWSManagedIPDDoSList` (default **Count**): IPs identified as participating in DDoS activities, including open proxies and potentially some residential proxies that are exploited as DDoS relay points

AWSManagedIPDDoSList defaults to Count because these IPs may belong to legitimate users whose devices were temporarily compromised — blocking them outright would cause false positives.

**Relationship with AntiDDoS AMR**: AntiDDoS AMR has built-in capability to handle IPs on the ManagedIPDDoSList. When AntiDDoS AMR is deployed, AWSManagedIPDDoSList is not needed — AMR subsumes its functionality. However, if the user does not deploy AntiDDoS AMR, AWSManagedIPDDoSList at default Count only adds a label without taking action. A downstream rule (e.g., a rate-based rule with the DDoS IP label as scope-down) is needed to make it effective.

### AWSManagedRulesAnonymousIpList (WCU: 50)
- `AnonymousIPList` (default Block): TOR nodes, temporary proxies, masking services
- `HostingProviderIPList` (default Block): cloud hosting and web hosting provider IPs

**HostingProviderIPList outdated assumption**: This rule assumes legitimate users don't originate from cloud platforms. This is increasingly false — many enterprises route traffic through cloud-based proxies, VPNs, or SaaS gateways, and many websites serve both enterprise and consumer traffic on the same domain. Default Block frequently causes false positives. Best practice: override to **Count** and optionally use the label for downstream rate limiting. Override to Allow is dangerous — it lets cloud-hosted attack traffic bypass all subsequent rules.

## ASN Match Statement

- Match requests by source IP's Autonomous System Number
- Syntax: `"AsnMatchStatement": { "AsnList": [15169, 8075] }`
- Use case: identify legitimate search engine crawlers. Confirmed ASNs: Google ASN 15169, Bing ASN 8075, Yandex ASN 13238 and 208722. For other search engines (Baidu, Yahoo Japan, etc.), verify the current ASN list from their official documentation — these engines may use multiple ASNs.
- Combine with User-Agent for double verification (ASN is unforgeable, UA is forgeable)
- Reference: https://aws.amazon.com/cn/blogs/china/aws-waf-guide-10-using-amazon-q-developer-cli-to-solve-conflicts-between-ddos-protection-and-seo/

## ASN + UA Crawler Labeling Rule

The recommended way to identify verified search engine crawlers is a dedicated Count+Label rule placed **before** any rule that needs to exclude crawlers. This rule uses ASN + User-Agent double verification:
- **ASN** is unforgeable — it identifies the actual network the request originates from
- **User-Agent** alone is forgeable, but combined with ASN it becomes reliable

Once labeled, downstream rules (AntiDDoS AMR, Always-on Challenge, etc.) can exclude crawlers via a simple `LabelMatchStatement` in their scope-down, without duplicating the ASN+UA logic.

### Why not use Bot Control's `bot:verified` label instead?
Bot Control Common level does identify verified search engine crawlers and adds the `bot:verified` label. However, Bot Control must be placed **last** in the Web ACL (it is the most expensive rule group at $1–$10/million requests; placing it last minimizes the number of requests it evaluates). This means `bot:verified` does not exist yet when AntiDDoS AMR and Always-on Challenge evaluate the request — both of which must be placed before Bot Control. The ASN+UA labeling rule is therefore always required when crawler exclusion is needed, regardless of whether Bot Control is present.

### Rule JSON

```json
{
  "Name": "label-verified-crawlers",
  "Priority": 5,
  "Action": {
    "Count": {}
  },
  "RuleLabels": [
    { "Name": "crawler:verified" }
  ],
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "label-verified-crawlers"
  },
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "AndStatement": {
            "Statements": [
              {
                "ByteMatchStatement": {
                  "SearchString": "googlebot",
                  "FieldToMatch": { "SingleHeader": { "Name": "user-agent" } },
                  "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
                  "PositionalConstraint": "CONTAINS"
                }
              },
              {
                "AsnMatchStatement": { "AsnList": [15169] }
              }
            ]
          }
        },
        {
          "AndStatement": {
            "Statements": [
              {
                "ByteMatchStatement": {
                  "SearchString": "bingbot",
                  "FieldToMatch": { "SingleHeader": { "Name": "user-agent" } },
                  "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
                  "PositionalConstraint": "CONTAINS"
                }
              },
              {
                "AsnMatchStatement": { "AsnList": [8075] }
              }
            ]
          }
        },
        {
          "AndStatement": {
            "Statements": [
              {
                "ByteMatchStatement": {
                  "SearchString": "yandexbot",
                  "FieldToMatch": { "SingleHeader": { "Name": "user-agent" } },
                  "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
                  "PositionalConstraint": "CONTAINS"
                }
              },
              {
                "AsnMatchStatement": { "AsnList": [13238, 208722] }
              }
            ]
          }
        }
      ]
    }
  }
}
```

### Confirmed ASNs
- Google: ASN 15169
- Bing (Microsoft): ASN 8075
- Yandex: ASN 13238 and ASN 208722

For other search engines (Baidu, Yahoo Japan, etc.), do NOT assume a single ASN covers all crawler IPs. Advise the user to verify the current ASN list from the search engine's official documentation before configuring.

### Extensibility
To add more search engines, add more `AndStatement` branches inside the `OrStatement`. No changes needed to downstream rules — they all consume the same `crawler:verified` label.

## Search Engine Crawler Exclusion Pattern

### Problem
Two rules in a typical DDoS-protection Web ACL will Challenge search engine crawlers:
1. **AntiDDoS AMR's `ChallengeAllDuringEvent`** — Challenges all challengeable requests during a DDoS event
2. **Always-on Challenge for HTML pages** — Challenges all `GET + Accept: text/html` requests continuously, not just during attacks

Search engine crawlers (Googlebot, Bingbot, etc.) may not reliably complete JavaScript Challenge. Real-world cases have been observed where crawlers indexed the Challenge interstitial page (HTTP 202 with JS) instead of actual content during DDoS events, severely damaging SEO rankings and search result appearance.

### Why not use Bot Control for this?
Bot Control Common level does identify verified crawlers and adds the `bot:verified` label — but Bot Control must be placed **last** in the Web ACL to minimize per-request costs. This means `bot:verified` does not exist yet when AntiDDoS AMR and Always-on Challenge evaluate the request. Cost aside, the ordering constraint alone makes Bot Control unsuitable for this purpose. See "ASN + UA Crawler Labeling Rule" for the correct approach.

### Solution
Place the "ASN + UA Crawler Labeling Rule" (see above) at a higher priority (lower number) than both AntiDDoS AMR and Always-on Challenge. Then configure each of those rules to exclude requests carrying the `crawler:verified` label via their scope-down.

This single labeling rule serves both downstream consumers — no duplication of ASN+UA logic needed.

## Always-on Challenge for HTML Pages

### Why it is effective for DDoS protection
- Most DDoS attack tools are not real browsers — they cannot execute JavaScript and therefore cannot pass Challenge or obtain a WAF token
- Always-on Challenge is preventive, not reactive: it filters non-browser traffic continuously, without waiting for AntiDDoS AMR to detect an attack
- **Takes effect immediately with zero detection delay** — attack traffic is blocked from the first request, unlike AntiDDoS AMR which requires time to establish a baseline before it can detect anomalies
- Legitimate users with a valid WAF token are not affected: Challenge acts like Count for requests with an unexpired token, so real users experience the JS verification only once, then browse uninterrupted for the token's lifetime
- **Severity when absent**: Medium — this is the most effective proactive DDoS defense for browser traffic; its absence means the Web ACL relies entirely on reactive AMR detection with an unavoidable delay window

### What it affects and what it does NOT affect
Always-on Challenge only matches requests where the `Accept` header contains `text/html` (contains match, not exact) and the method is `GET`. This means:
- ✅ Affects: browser navigation requests (HTML pages)
- ❌ Does NOT affect: API calls (JSON/XML responses), file downloads, native app traffic, SPA API requests, static assets (CSS/JS/images), POST/PUT/DELETE requests, CORS preflight OPTIONS requests

This narrow scope means always-on Challenge can be safely deployed without impacting APIs, native apps, file downloads, or single-page application backends.

### Token immunity time
- Default immunity time is 300 seconds (5 minutes), which works but may concern some users about UX impact
- Recommend extending to at least 4 hours (14400 seconds) for always-on Challenge — real users complete the JS verification once and then browse uninterrupted for the entire immunity period
- Configurable at the rule level or Web ACL level

### Search engine crawler consideration
- Search engine crawlers send `GET` requests with `Accept: text/html` — they match the always-on Challenge condition and will be challenged on every request, not just during DDoS events
- Search engine crawlers may not reliably complete JavaScript Challenge — real-world cases show crawlers indexing the Challenge interstitial page instead of actual content, so always-on Challenge can continuously disrupt crawler indexing
- Solution: place the "ASN + UA Crawler Labeling Rule" (see "ASN + UA Crawler Labeling Rule" section) before this rule, then exclude requests with the `crawler:verified` label in the Challenge rule's scope-down (see the always-on-challenge-html rule JSON in checklist.md section 16 for an example that includes this exclusion)

### Complementary to AntiDDoS AMR
- AntiDDoS AMR is reactive: it detects anomalies and then starts mitigating
- Always-on Challenge is proactive: it requires proof of browser capability before any HTML content is served
- Together they provide defense in depth: always-on Challenge handles the bulk of non-browser DDoS traffic instantly, while AntiDDoS AMR handles sophisticated attacks that use real browsers or target non-challengeable paths

## AWSManagedRulesCommonRuleSet (CRS) Notes

- Provides OWASP Top 10 protection (SQLi, XSS, etc.)
- `SizeRestrictions_Body` rule blocks request bodies larger than 8KB. This frequently causes false positives on file upload endpoints, API endpoints with large payloads, form submissions with rich content, etc. Most users don't know which of their endpoints need large bodies. When recommending CRS, always advise overriding `SizeRestrictions_Body` to Count.

## AWSManagedRulesKnownBadInputsRuleSet Notes

- Protects against known malicious input patterns: Log4j/Log4Shell (CVE-2021-44228), Java deserialization exploits, and other well-known attack payloads
- Low WCU cost, low false positive rate — generally safe to enable with default actions
- Recommended as a baseline rule group alongside CRS

## Token Domain Configuration

- `token_domains` should include the apex domain (e.g., `example.com`), which automatically covers all single-level subdomains (`www.example.com`, `sub.example.com`, i.e., `*.example.com`)
- No need to list each subdomain separately
- Wildcard (`*`) is NOT needed and should not be used
- Multi-level subdomains (e.g., `a.b.example.com`) require separate entries — the apex domain `example.com` only covers `*.example.com` (one level of subdomain). For `a.b.example.com`, add `b.example.com` to `token_domains`.

## Web ACL Capacity Units (WCU)

- Each Web ACL has a maximum capacity of **5000 WCU**
- Each rule and rule group consumes WCU based on its complexity (statement types, number of conditions, etc.)
- WCU cannot be accurately calculated from JSON alone — the AWS console or API shows the actual WCU usage
- When recommending adding new rules or rule groups, always remind the user to verify remaining WCU capacity

## Recommended Rule Priority Order

The following is a recommended ordering for rules in a Web ACL. Not all rule types are present in every Web ACL — skip those that don't apply.

1. **IP whitelist (Allow)** — Trusted IPs (monitoring probes, internal services, etc.) bypass all subsequent rules. Volume is typically small and does not materially affect AntiDDoS AMR baseline.
2. **IP blacklist (Block)** — Known malicious IPs blocked immediately. Keeps them out of AntiDDoS AMR baseline, which actually improves baseline accuracy.
3. **Count+Label rules** — Tag traffic types (e.g., native app identification, crawler identification via ASN+UA) for use by downstream rules' scope-down conditions. Must be placed before any rule that consumes these labels.
4. **AntiDDoS AMR** — Needs to see as much traffic as possible to build an accurate baseline. Place as early as possible, but after IP whitelist/blacklist and any labeling rules it depends on for scope-down (e.g., native app label for dual-AMR, crawler label for SEO exclusion).
5. **IP reputation rule group** (AWSManagedRulesAmazonIpReputationList) — Low WCU (25), filters known malicious IPs. Placed after AntiDDoS AMR so AMR sees the full traffic pattern.
6. **Anonymous IP rule group** (AWSManagedRulesAnonymousIpList) — Filters anonymous/hosting provider IPs. Placed after AMR for the same reason.
7. **Rate-based rules** — Rate limiting as a defense layer. Placed before Always-on Challenge to reduce the volume of requests that reach Challenge.
8. **Always-on Challenge for HTML pages** — Proactive DDoS defense for browser traffic. Placed after IP reputation, Anonymous IP, and rate-based rules so that traffic already filtered by those rules does not incur Challenge costs.
9. **Custom rules** — Business-specific logic including geo-blocking, URI-based rules, header-based rules, etc.
10. **Application layer rule groups** (CRS, KnownBadInputs, SQLi, etc.) — OWASP Top 10 and application-specific protections. Placed after custom rules so that business-specific Allow/Block decisions take precedence.
11. **Bot Control, ATP, ACFP** (optional) — Per-request pricing rule groups. Place last to minimize the number of requests they evaluate. Bot Control is the most expensive at Targeted level ($10/million requests). ATP and ACFP also use per-request pricing and should be grouped here.

**Key principles:**
- Label producers before label consumers
- AntiDDoS AMR as early as possible for accurate baseline — other rules placed after it so AMR sees full traffic
- Cost optimization: cheaper rules first to filter traffic before it reaches expensive rules
- Terminating rules (Allow/Block) placed early should be scrutinized — they cause traffic to skip all subsequent rules

## Managed Rule Group Action Overrides

### Version recommendations
Only these managed rule groups have significant version upgrades worth flagging:
- **AWSManagedRulesSQLiRuleSet**: version 2.0 has significantly higher SQLi detection coverage than the default 1.0. Recommend upgrading if pinned below 2.0.
- **AWSManagedRulesBotControlRuleSet**: version 5.0's Common level can identify close to 700 bot types (up from far fewer in 1.0) based on UA and IP, and Targeted level includes substantially more detection rules. The default version is still 1.0, which is outdated. Recommend upgrading if pinned below 5.0.

For all other managed rule groups, the version shown in JSON is just the current snapshot and requires no action.

### How overrides work
- Each rule inside a managed rule group has a default action (Block, Count, Challenge, etc.)
- You can override individual rules to a different action (e.g., Block → Count, Block → Allow)
- Overriding to Count: the request continues to the NEXT rule within the same rule group, then to subsequent rules in the Web ACL. Labels from the Count-overridden rule are still added.
- Overriding to Allow: the request is IMMEDIATELY allowed and skips ALL remaining rules (both within the group and in the Web ACL). This is the most dangerous override.
- Overriding to Block: the request is immediately blocked.

### Key implications
- Override to Count on one rule may expose traffic to a stricter rule later in the same group
- Override to Allow on one rule bypasses all subsequent protections — not just the current rule group
- When reviewing overrides, consider the rule's position within the group and what comes after it

## Common Anti-patterns

### Count action as labeling mechanism
- Count is non-terminating: the request continues to subsequent rules
- Count rules often add custom labels used by downstream rules for scope-down or conditional logic
- This is a legitimate and common pattern ("label then act"), not an anti-pattern itself
- However, changing a Count rule to Block/Allow breaks this pattern — downstream rules lose the label and may behave unexpectedly
- When reviewing Count rules, always check if any later rule references labels produced by this rule
- **Count without labels**: A custom Count rule (not AWS managed) with no `RuleLabels` entry only contributes a CloudWatch metric — downstream rules have no way to act on its match result. This may be intentional (monitoring only) or a misconfiguration (user intended "label then act" but forgot to add labels).

### Allow based on forgeable conditions
- User-Agent prefix matching → attacker forges UA to bypass all rules
- Business cookie existence check → attacker adds cookie to bypass
- Any custom header value → attacker adds header to bypass

**Forgeable conditions** (attacker can set freely): User-Agent, cookies, custom headers, query parameters, request body content.

**Unforgeable conditions** (attacker cannot control): IP set, WAF token (`aws-waf-token` cookie — cryptographically signed by AWS), HMAC signature (if validated server-side), ASN match (based on source IP's network).

### HostingProviderIPList misconfiguration
- Default Block → frequent false positives for enterprise traffic routed through cloud platforms. Override to Count.
- Override to Allow → cloud-hosted attacks bypass all rules. Override to Count instead.
- See "IP Reputation Rule Groups" section for full details.

### Count rules with Challenge/Block intent (staging risk)
- Users often deploy rules in Count mode first to evaluate impact before switching to the intended action (Challenge, Block, etc.)
- The rule name often reveals the intended action (e.g., `challenge_all_traffic`, `block_suspicious_ips_staging`)
- Risk: the user may not realize that their statement, when combined with the intended action, would cause unintended collateral damage. For example, a rule that matches all traffic (or all traffic minus a few excluded paths) set to Challenge would effectively Block all POST requests, API calls, and native app traffic — because those requests cannot complete Challenge.
- This is especially dangerous for broad-match rules intended to become Challenge: the user sees Count metrics showing "X requests matched" and thinks "great, I'll flip it to Challenge" — not realizing that a large portion of those matched requests will be effectively Blocked, not Challenged.
- Always evaluate the statement as if the action were already the intended action, and flag any mismatch between the statement's scope and what the intended action can actually handle.

### Scope-down too narrow
- `URI EXACTLY "/"` on IP reputation rules → only homepage checked
- Effectively disables the rule group for all other paths

### Disabling core protections with weak fallbacks
- ChallengeAllDuringEvent → Count, relying on Bot Control as fallback
- Bot Control has different purpose, slower response, higher cost, narrower scope

### Override to Allow when default already handles the case
- CategorySearchEngine/CategorySeo Allow → category rules only match unverified bots; verified bots already pass without action; forged UAs never match category rules and are handled by SignalNonBrowserUserAgent. Allow override lets unverified search engine bots bypass all subsequent rules. See "Common level common misconfigurations" for details.
