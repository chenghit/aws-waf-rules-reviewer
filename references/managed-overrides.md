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
3. **Count+Label rules** — Tag traffic types (e.g., native app identification, crawler identification via ASN+UA, landing page URI labeling) for use by downstream rules' scope-down conditions. Must be placed before any rule that consumes these labels.
4. **AntiDDoS AMR** — Needs to see as much traffic as possible to build an accurate baseline. Place as early as possible, but after IP whitelist/blacklist and any labeling rules it depends on for scope-down (e.g., native app label for dual-AMR, crawler label for SEO exclusion).
5. **IP reputation rule group** (AWSManagedRulesAmazonIpReputationList) — Low WCU (25), filters known malicious IPs. Placed after AntiDDoS AMR so AMR sees the full traffic pattern.
6. **Anonymous IP rule group** (AWSManagedRulesAnonymousIpList) — Filters anonymous/hosting provider IPs. Placed after AMR for the same reason.
7. **Rate-based rules** — Rate limiting as a defense layer. Placed before Always-on Challenge to reduce the volume of requests that reach Challenge.
8. **Always-on Challenge for landing pages** (Challenge rule only) — Proactive DDoS defense. Consumes the `custom:landing-page` label produced by the Count+Label rule in position 3. Placed after IP reputation, Anonymous IP, and rate-based rules so that traffic already filtered by those rules does not incur Challenge costs.
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

