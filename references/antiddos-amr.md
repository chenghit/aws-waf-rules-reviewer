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

