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

### Verified vs unverified bots
- Common rules (CategorySearchEngine, CategorySeo, etc.) default action is Block, but **only for unverified bots**
- For verified bots: rule does NOT match, no action taken, only labels added (`bot:verified`)
- Override to Allow is unnecessary for verified bots and dangerous — it also allows unverified (forged) bots

### Token labels
- `awswaf:managed:token:absent/accepted/rejected` — ONLY produced when Bot Control, ATP, or ACFP evaluates the request
- NOT produced by AntiDDoS AMR or other rule groups
- `token:absent` means request has no WAF token

### Key rules for native app considerations
- `SignalNonBrowserUserAgent` (default Block): blocks non-browser User-Agents
- `TGT_TokenAbsent` (default Count, often overridden to Challenge): flags requests without WAF token
- `TGT_VolumetricIpTokenAbsent` (default Challenge): 5+ requests from same IP without token in 5 min

### Targeted level
- `inspection_level: TARGETED` with `enable_machine_learning: true`
- Uses behavior analysis, fingerprinting, browser interrogation
- Per-request pricing: $10/million requests (expensive)
- Designed for advanced bot detection (credential stuffing, inventory hoarding), NOT for volumetric DDoS

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
- HostingProviderIPList Allow → cloud-hosted attacks bypass all rules

### Scope-down too narrow
- `URI EXACTLY "/"` on IP reputation rules → only homepage checked
- Effectively disables the rule group for all other paths

### Disabling core protections with weak fallbacks
- ChallengeAllDuringEvent → Count, relying on Bot Control as fallback
- Bot Control has different purpose, slower response, higher cost, narrower scope

### Override to Allow when default already handles the case
- CategorySearchEngine/CategorySeo Allow → verified bots already pass by default
- Override lets unverified (forged) bots through too
