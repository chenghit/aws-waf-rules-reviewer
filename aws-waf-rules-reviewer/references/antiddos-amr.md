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
When browser and native app traffic need different strategies, use two AMR instances with different scope-downs and sensitivity settings. See **Appendix B** in the review report for the full implementation steps.

### SEO: excluding search engine crawlers from AntiDDoS AMR
`ChallengeAllDuringEvent` will Challenge all challengeable requests during a DDoS event, including search engine crawlers. Although modern crawlers may support JavaScript execution, real-world cases have been observed where crawlers indexed the Challenge interstitial page (HTTP 202) instead of actual content during DDoS events, severely damaging SEO. The root cause is not fully understood — it may be that crawlers behave differently under high-load conditions, or that the Challenge interstitial is served in a context where the crawler does not retry after token acquisition.

The solution is to place the "ASN + UA Crawler Labeling Rule" (see crawler-seo.md) before AntiDDoS AMR, then add a scope-down to AntiDDoS AMR that excludes requests with the `crawler:verified` label. See **Appendix B** for the scope-down JSON.

