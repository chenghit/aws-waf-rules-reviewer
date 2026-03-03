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

## CAPTCHA Action

### How it works
- Returns HTTP 405 with a visible image puzzle interstitial
- User must solve the puzzle; on success, client gets/updates `aws-waf-token` cookie
- Unlike Challenge, CAPTCHA **always shows the puzzle** regardless of whether the client already has a valid token

### What can complete CAPTCHA
- Same constraints as Challenge: browser `GET` requests with `Accept: text/html` over HTTPS

### What cannot complete CAPTCHA
- Same as Challenge: `POST` requests, API calls, native apps, non-`GET` requests, non-browser clients
- **For POST/API paths, CAPTCHA is effectively equivalent to Block** — the interstitial cannot be completed, so the original request is never resubmitted

### Key difference from Challenge
- Challenge: silent JS puzzle, token-aware (skips if valid token exists)
- CAPTCHA: visible image puzzle, always shown regardless of token state
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
- `awswaf:managed:aws:anti-ddos:challengeable-request` — GET + URI not matching exempt regex
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
2. AMR instance 1 (browser traffic): scope-down to exclude the native app label, `ChallengeAllDuringEvent` enabled, Block LOW
3. AMR instance 2 (native app traffic): scope-down to match the native app label only, `ChallengeAllDuringEvent` disabled, Block MEDIUM

Implementation: In the Web ACL JSON editor, copy the existing AMR rule entry, paste it as a new custom rule, change the `Name` and `MetricName` fields to unique values, then save. AWS WAF treats them as two independent rule instances.

## Bot Control (AWSManagedRulesBotControlRuleSet)

### Common level
- Identifies self-declared bots by analyzing the User-Agent header
- Bots fall into three categories based on how Common level handles them:
  1. **Verified bots** — UA claims to belong to a specific organization (e.g., Googlebot, Bingbot, Route53 Health Check) AND reverse DNS lookup confirms the source IP belongs to that organization. The matching category rule adds labels (`bot:verified` + category + name) but takes **no action**. Bot Control evaluation ends here; the request continues to subsequent Web ACL rules.
  2. **Unverified bots** — UA identifies the bot as belonging to a known category, but the bot cannot be verified via reverse DNS. This includes: bots not belonging to any specific organization (e.g., okhttp, WhatsApp), bots triggered by individual users on personal devices, bots whose business model doesn't involve visiting websites (e.g., scanners, curl), and bots from organizations where individual-triggered requests can't be reverse-DNS-verified (e.g., some Google SaaS developer tools). The matching category rule adds labels (`bot:unverified` + category + name) and applies the **default action (Block)**.
  3. **Unknown non-browser UA** — UA is neither a browser UA nor any recognized bot UA, OR it claims to be an organization bot but reverse DNS verification fails (forged UA). These requests do NOT match any category rule. They fall through to `SignalNonBrowserUserAgent`, which adds `signal:non_browser_user_agent` and applies the **default action (Block)**.
- Can identify 200+ bot types

### Common level limitations
- **Only detects bots that self-identify via User-Agent.** If a bot uses a standard browser User-Agent (e.g., Chrome or Firefox UA), Common level will not detect it at all — the request passes through Bot Control as if it were a normal browser request.
- No behavioral analysis, no browser fingerprinting, no ML-based detection
- Cannot detect: credential stuffing bots, scraping bots using real browser UAs, headless browsers, automated tools that mimic human behavior
- Common level is a UA-based classifier, not a bot defense solution for advanced threats

### Common level common misconfigurations

**Overriding CategorySearchEngine/CategorySeo to Allow to "protect SEO":**
This is unnecessary and potentially harmful, but the actual risk is more nuanced than it appears. Category rules only match **unverified** bots in that category — bots that self-identify as search engine crawlers but cannot be verified via reverse DNS (e.g., individual-triggered Google SaaS tools, personal-device bots). Verified crawlers (e.g., real Googlebot with confirmed reverse DNS) are already handled without any action by the category rule — they pass through with `bot:verified` label regardless of the override. Forged Googlebot UAs (reverse DNS fails) do NOT match `CategorySearchEngine` at all — they fall through to `SignalNonBrowserUserAgent` and are Blocked. Therefore, overriding `CategorySearchEngine` to Allow only affects unverified search engine bots (which would otherwise be Blocked), allowing them to bypass all subsequent WAF rules. Severity: **Low** — the blast radius is limited to unverified bots in that category; it does not enable full WAF bypass for arbitrary attackers. The correct approach: keep default actions. If AntiDDoS AMR's ChallengeAllDuringEvent is a concern for crawlers, scope-down AntiDDoS AMR using ASN + UA double verification (see "Search Engine Crawler Exclusion Pattern"), not Bot Control Allow overrides.

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
- `awswaf:managed:token:absent/accepted/rejected` — ONLY produced when Bot Control, ATP, or ACFP evaluates the request
- NOT produced by AntiDDoS AMR or other rule groups
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

### Multiple rate-based rules with overlapping scope-downs
- If a Web ACL has multiple rate-based rules, and their scope-down conditions overlap or have a containing relationship (e.g., one targets `/api/` and another targets all traffic), only the rule with the lowest threshold will ever trigger for the overlapping traffic
- The other rules are effectively redundant for that traffic
- If the intent was different rate limits for different traffic types, scope-downs should be adjusted to be mutually exclusive

## IP Reputation Rule Groups

### AWSManagedRulesAmazonIpReputationList (WCU: 25)
Contains three rules:
- `AWSManagedIPReputationList` (default Block): known malicious IPs from Amazon threat intelligence (MadPot)
- `AWSManagedReconnaissanceList` (default Block): IPs performing reconnaissance against AWS resources
- `AWSManagedIPDDoSList` (default **Count**): IPs identified as participating in DDoS activities

AWSManagedIPDDoSList defaults to Count because DDoS IP lists change rapidly — an IP may be a compromised host (botnet) that has since recovered, but the list update lags behind. Blocking by default would risk false positives.

**Relationship with AntiDDoS AMR**: AntiDDoS AMR only acts after detecting a DDoS event. During normal times and during the detection delay at the start of an attack, known DDoS IPs are not blocked by AMR. AWSManagedIPDDoSList fills this gap by providing IP-intelligence-based protection that is always active.

### AWSManagedRulesAnonymousIpList (WCU: 50)
- `AnonymousIPList` (default Block): TOR nodes, temporary proxies, masking services
- `HostingProviderIPList` (default Block): cloud hosting and web hosting provider IPs

**HostingProviderIPList outdated assumption**: This rule assumes legitimate users don't originate from cloud platforms. This is increasingly false — many enterprises route traffic through cloud-based proxies, VPNs, or SaaS gateways, and many websites serve both enterprise and consumer traffic on the same domain. Default Block frequently causes false positives. Best practice: override to **Count** and optionally use the label for downstream rate limiting. Override to Allow is dangerous — it lets cloud-hosted attack traffic bypass all subsequent rules.

## ASN Match Statement

- Match requests by source IP's Autonomous System Number
- Syntax: `"AsnMatchStatement": { "AsnList": [15169, 8075] }`
- Use case: identify legitimate search engine crawlers. Confirmed ASNs: Google ASN 15169, Bing ASN 8075, Yandex ASN 13238. For other search engines (Baidu, Yahoo Japan, etc.), verify the current ASN list from their official documentation — these engines may use multiple ASNs.
- Combine with User-Agent for double verification (ASN is unforgeable, UA is forgeable)
- Reference: https://aws.amazon.com/cn/blogs/china/aws-waf-guide-10-using-amazon-q-developer-cli-to-solve-conflicts-between-ddos-protection-and-seo/

## Search Engine Crawler Exclusion Pattern

### Problem
AntiDDoS AMR's ChallengeAllDuringEvent rule Challenges all challengeable requests during a DDoS event. Search engine crawlers (Googlebot, Bingbot, etc.) cannot execute JavaScript Challenge. When challenged, crawlers may index the Challenge interstitial page (HTTP 202 with JS) instead of actual content, severely damaging SEO rankings and search result appearance.

### Why not use Bot Control for this?
Bot Control can identify verified crawlers, but it costs $10/million requests (Targeted level) or $1/million (Common level). For AntiDDoS scenarios where the goal is simply to exclude crawlers from Challenge, this is unnecessarily expensive.

### Solution: ASN + User-Agent double verification scope-down
Apply a scope-down to the AntiDDoS AMR rule group that excludes requests matching BOTH:
1. User-Agent contains a search engine bot keyword (e.g., "googlebot", "bingbot") — forgeable alone, but combined with ASN becomes reliable
2. Source IP belongs to the search engine's ASN (unforgeable) — Google: ASN 15169, Bing: ASN 8075

### Scope-down structure
The scope-down uses a NOT(Or(And, And)) pattern:
- NOT → "inspect everything EXCEPT the following"
  - OR → "any of these crawler patterns"
    - AND → UA contains "googlebot" AND ASN is 15169
    - AND → UA contains "bingbot" AND ASN is 8075

This ensures AntiDDoS AMR inspects all traffic except verified search engine crawlers.

### Extensibility
The same pattern can be extended for other search engines by adding more AND branches inside the OR statement. Confirmed examples:
- Yandex: UA contains "yandexbot", ASN 13238 and ASN 208722

For other search engines (Baidu, Yahoo Japan, etc.), do NOT assume a single ASN covers all crawler IPs — these engines may use multiple ASNs. Advise the user to verify the current ASN list from the search engine's official documentation before configuring.

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
- Search engine crawlers send `GET` requests with `Accept: text/html` — they will be challenged
- Crawlers cannot complete JavaScript Challenge, so always-on Challenge will block them
- Solution: place the always-on Challenge rule AFTER a Count+Label rule that identifies legitimate crawlers via ASN + User-Agent double verification (see "Search Engine Crawler Exclusion Pattern"), then scope-down the Challenge rule to exclude requests with the crawler label

### Complementary to AntiDDoS AMR
- AntiDDoS AMR is reactive: it detects anomalies and then starts mitigating
- Always-on Challenge is proactive: it requires proof of browser capability before any HTML content is served
- Together they provide defense in depth: always-on Challenge handles the bulk of non-browser DDoS traffic instantly, while AntiDDoS AMR handles sophisticated attacks that use real browsers or target non-challengeable paths

## AWSManagedRulesCommonRuleSet (CRS) Notes

- Provides OWASP Top 10 protection (SQLi, XSS, etc.)
- `SizeRestrictions_Body` rule blocks request bodies larger than 8KB. This frequently causes false positives on file upload endpoints, API endpoints with large payloads, form submissions with rich content, etc. Most users don't know which of their endpoints need large bodies. When recommending CRS, always advise overriding `SizeRestrictions_Body` to Count.

## Token Domain Configuration

- `token_domains` should include the apex domain (e.g., `example.com`), which automatically covers all subdomains up to 3rd level (`www.example.com`, `sub.example.com`, etc.)
- No need to list each subdomain separately
- Wildcard (`*`) is NOT needed and should not be used
- 4th-level domains (e.g., `a.b.example.com`) require separate entries — apex domain coverage does not extend that deep

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
11. **Bot Control** (optional) — Most expensive rule group (per-request pricing at Targeted level). Place last to minimize the number of requests it evaluates. Only configure if the Web ACL requires bot detection beyond what other rules provide.

**Key principles:**
- Label producers before label consumers
- AntiDDoS AMR as early as possible for accurate baseline — other rules placed after it so AMR sees full traffic
- Cost optimization: cheaper rules first to filter traffic before it reaches expensive rules
- Terminating rules (Allow/Block) placed early should be scrutinized — they cause traffic to skip all subsequent rules

## Managed Rule Group Action Overrides

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

### Allow based on forgeable conditions
- User-Agent prefix matching → attacker forges UA to bypass all rules
- Business cookie existence check → attacker adds cookie to bypass

### HostingProviderIPList misconfiguration
- Default Block → frequent false positives for enterprise traffic routed through cloud platforms. Override to Count.
- Override to Allow → cloud-hosted attacks bypass all rules. Override to Count instead.
- See "IP Reputation Rule Groups" section for full details.

### Scope-down too narrow
- `URI EXACTLY "/"` on IP reputation rules → only homepage checked
- Effectively disables the rule group for all other paths

### Disabling core protections with weak fallbacks
- ChallengeAllDuringEvent → Count, relying on Bot Control as fallback
- Bot Control has different purpose, slower response, higher cost, narrower scope

### Override to Allow when default already handles the case
- CategorySearchEngine/CategorySeo Allow → category rules only match unverified bots; verified bots already pass without action; forged UAs never match category rules and are handled by SignalNonBrowserUserAgent. Allow override lets unverified search engine bots bypass all subsequent rules. See "Common level common misconfigurations" for details.
