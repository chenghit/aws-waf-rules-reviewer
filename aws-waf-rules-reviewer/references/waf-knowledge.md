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
- API paths without `^` are contains matches, not starts-with
- Example: `^\/api\/|^\/query|\.(css|js|png)$`

### Pricing
- $20/month per AMR instance + $0.15/million requests
- DDoS traffic detected and mitigated is NOT charged

### Dual instance pattern
When browser and native app traffic need different strategies:
1. Pre-label native app requests (high priority rule)
2. AMR instance 1: exclude native app label, enable Challenge, Block LOW
3. AMR instance 2: match native app label only, disable Challenge, Block MEDIUM

Implementation: copy AMR JSON → create custom rule → change name/metric → save

## Bot Control (AWSManagedRulesBotControlRuleSet)

### Common level
- Identifies self-declared bots by analyzing the User-Agent header
- For bots claiming to belong to a specific organization (e.g., Googlebot, Bingbot, Route53 Health Check): performs **reverse DNS lookup** on the source IP to verify the User-Agent is genuine. If the resolved domain belongs to the claimed organization → verified; otherwise → forged
- For bots not belonging to a specific organization (e.g., okhttp, WhatsApp): reverse DNS lookup is not meaningful, so the rule does not verify — marks as `bot:unverified` and applies default action (Block)
- Can identify 200+ bot types

### Common level limitations
- **Only detects bots that self-identify via User-Agent.** If a bot uses a standard browser User-Agent (e.g., Chrome or Firefox UA), Common level will not detect it at all — the request passes through Bot Control as if it were a normal browser request.
- No behavioral analysis, no browser fingerprinting, no ML-based detection
- Cannot detect: credential stuffing bots, scraping bots using real browser UAs, headless browsers, automated tools that mimic human behavior
- Common level is a UA-based classifier, not a bot defense solution for advanced threats

### Common level common misconfigurations

**Overriding CategorySearchEngine/CategorySeo to Allow to "protect SEO":**
This is a serious mistake. Common Bot Control already does not block verified search engine crawlers — verified bots (those passing reverse DNS verification) receive only labels and no action. The request then continues to subsequent rules. Overriding to Allow is unnecessary and dangerous: Allow is a terminating action that does not distinguish verified from unverified. A malicious bot forging a Googlebot User-Agent (which fails reverse DNS) would also be Allowed, bypassing all subsequent WAF rules. The correct approach: keep default actions. If AntiDDoS AMR's ChallengeAllDuringEvent is a concern for crawlers, scope-down AntiDDoS AMR using ASN + UA double verification (see "Search Engine Crawler Exclusion Pattern"), not Bot Control Allow overrides.

**Keeping SignalNonBrowserUserAgent and CategoryHttpLibrary at default Block:**
These two rules block requests with non-browser User-Agents. Default Block frequently causes false positives on legitimate non-browser clients (native apps, API clients, monitoring tools, legitimate HTTP libraries). Best practice is to override both to **Count**. This preserves the labeling (for downstream rules to use) while avoiding false positives.

### Common level key labels
- `bot:verified` — User-Agent verified via reverse DNS. Bot Control stops checking this request; it passes to subsequent Web ACL rules
- `bot:unverified` — Bot identified but cannot be verified (not from a specific organization). Default action: Block
- `signal:non_browser_user_agent` — Either: (1) reverse DNS verification failed (forged UA), or (2) UA is neither a browser nor a known bot. Default action: Block

### Verified vs unverified bots
- For verified bots: the matching rule does NOT take action, only adds labels (`bot:verified` + category + name). Bot Control evaluation ends here.
- For unverified bots: the matching rule applies its default action (usually Block)
- Override to Allow is unnecessary for verified bots and dangerous — it also allows unverified/forged bots

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
- `SignalNonBrowserUserAgent` (default Block): blocks non-browser User-Agents that fail verification or are unknown. Best practice is to override to **Count** to avoid false positives (see "Common level common misconfigurations").
- `TGT_TokenAbsent` (default Count, often overridden to Challenge): flags requests without WAF token
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

## ASN Match Statement (June 2025)

- Match requests by source IP's Autonomous System Number
- Syntax: `"AsnMatchStatement": { "AsnList": [15169, 8075] }`
- Use case: identify legitimate search engine crawlers (Google ASN 15169, Bing ASN 8075)
- Combine with User-Agent for double verification (ASN is unforgeable, UA is forgeable)
- Reference: https://aws.amazon.com/cn/blogs/china/aws-waf-guide-10-using-amazon-q-developer-cli-to-solve-conflicts-between-ddos-protection-and-seo/

## Search Engine Crawler Exclusion Pattern

### Problem
AntiDDoS AMR's ChallengeAllDuringEvent rule Challenges all challengeable requests during a DDoS event. Search engine crawlers (Googlebot, Bingbot, etc.) cannot execute JavaScript Challenge. When challenged, crawlers may index the Challenge interstitial page (HTTP 202 with JS) instead of actual content, severely damaging SEO rankings and search result appearance.

### Why not use Bot Control for this?
Bot Control can identify verified crawlers, but it costs $10/million requests (Targeted level) or $1/million (Common level). For AntiDDoS scenarios where the goal is simply to exclude crawlers from Challenge, this is unnecessarily expensive.

### Solution: ASN + User-Agent double verification scope-down
Apply a scope-down to the AntiDDoS AMR rule group that excludes requests matching BOTH:
1. User-Agent contains a search engine keyword (e.g., "google", "bing") — forgeable alone, but combined with ASN becomes reliable
2. Source IP belongs to the search engine's ASN (unforgeable) — Google: ASN 15169, Bing: ASN 8075

### Scope-down structure
The scope-down uses a NOT(Or(And, And)) pattern:
- NOT → "inspect everything EXCEPT the following"
  - OR → "any of these crawler patterns"
    - AND → UA contains "google" AND ASN is 15169
    - AND → UA contains "bing" AND ASN is 8075

This ensures AntiDDoS AMR inspects all traffic except verified search engine crawlers.

### Extensibility
The same pattern can be extended for other search engines (Baidu, Yandex, etc.) by adding more AND branches inside the OR statement with the appropriate UA keyword and ASN.

## Always-on Challenge for HTML Pages

### Why it is effective for DDoS protection
- Most DDoS attack tools are not real browsers — they cannot execute JavaScript and therefore cannot pass Challenge or obtain a WAF token
- Always-on Challenge is preventive, not reactive: it filters non-browser traffic continuously, without waiting for AntiDDoS AMR to detect an attack
- This eliminates the detection delay inherent in AntiDDoS AMR — attack traffic is blocked from the first request
- Legitimate users with a valid WAF token are not affected: Challenge acts like Count for requests with an unexpired token, so real users experience the JS verification only once, then browse uninterrupted for the token's lifetime

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
- CategorySearchEngine/CategorySeo Allow → verified bots already pass by default, Allow override also lets forged bots through. See "Common level common misconfigurations" above for details.
- Override lets unverified (forged) bots through too
