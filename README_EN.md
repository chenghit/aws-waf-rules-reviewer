# AWS WAF Rules Reviewer

[中文版](README.md)

An [Agent Skill](https://agentskills.io) that reviews AWS WAF Web ACL configurations for security issues, misconfigurations, and optimization opportunities.

## What It Does

Given an AWS WAF Web ACL JSON export, this skill:

1. Builds a rule execution flow — mapping every rule's priority, action, labels, and dependencies
2. Runs through an 18-item checklist covering Allow rule audits, scope-down validation, AntiDDoS AMR configuration, Bot Control settings, SEO impact, rate limiting, cross-rule dependencies, and more
3. Generates a review report with severity-rated findings (Critical / Medium / Low / Awareness)
4. Includes a Mermaid flow diagram and detailed rule-by-rule execution trace as an appendix
5. Self-reviews the report for issues the checklist may have missed

## Installation

Copy the `aws-waf-rules-reviewer` directory (containing `SKILL.md` and `references/`) to your AI coding tool's skill directory. For example, in Kiro CLI:

```
~/.kiro/skills/aws-waf-rules-reviewer/
├── SKILL.md
└── references/
    ├── checklist.md
    └── waf-knowledge.md
```

Then configure your agent to load the skill. Refer to your tool's documentation for details.

## Input

An AWS WAF Web ACL configuration in JSON format. This is typically obtained by:

- Exporting from the AWS Console (Web ACL → "Download web ACL as JSON")
- Using the AWS CLI: `aws wafv2 get-web-acl --name <name> --scope <REGIONAL|CLOUDFRONT> --id <id>`

You can provide either a direct file path or a directory path containing the JSON file(s).

## Output

A Markdown report (`waf-review-report.md`) containing:

- **Summary table** — all findings with severity and impact at a glance
- **Detailed findings** — each issue with the affected rule, current state, problem description, and recommendation
- **Items needing user confirmation** — findings where business context may change the severity, marked with ⏳
- **Appendix: Rule Execution Flow** — a Mermaid diagram for visual overview, plus a detailed rule-by-rule list showing priorities, actions, labels produced/consumed, and dependencies

### Severity Levels

| Level | Meaning |
|-------|---------|
| 🔴 Critical | Attackers can bypass protection entirely, or a core mechanism is disabled |
| 🟡 Medium | Protection gap exists but requires specific conditions to exploit |
| 🟢 Low | Suboptimal configuration without direct security impact |
| 🔵 Awareness | Not a vulnerability — operational information the user should know |

## Checklist Coverage

The review covers 18 categories in two phases:

**Phase 1: Independent Checks**

1. Allow rules audit (forgeability, bypass risk)
2. Scope-down statements (too narrow / too broad)
3. AntiDDoS AMR configuration (ChallengeAllDuringEvent, exempt regex, SEO impact, dual instance pattern)
4. Challenge action applicability (POST/API/native app limitations, Count-to-Challenge staging risk)
5. Bot Control configuration (Allow override risks, verified vs unverified bots)
6. Rate-based rules (activation delay, threshold reasonableness, overlapping scope-down)
7. IP reputation and anonymous IP rules
8. Landing page and cookie-based logic
9. Missing baseline protections (CRS, KnownBadInputs)
10. WCU capacity awareness
11. Token domain configuration
12. Managed rule group versions
13. Logging and monitoring
14. Hashed/opaque search_string in byte_match_statement
15. Default action (redundant trailing Allow-all detection)
16. Always-on Challenge for HTML pages (proactive DDoS defense, immunity time, crawler exclusion)

**Phase 2: Global Cross-checks**

17. Cross-rule and label dependency analysis (label source verification + fix impact analysis)
18. Rule priority ordering (label producers before consumers)

## Version History

### v0.2 (2026-03-24)

Checklist reorganized from 20 items to 18 items (two phases). Old-to-new number mapping:

| Old # | New # | Change |
|-------|-------|--------|
| 1–5 | 1–5 | Unchanged |
| 6 | 17a | Merged into Phase 2 "Cross-rule and label dependency analysis" |
| 7 | 6 | Renumbered |
| 8 | 7 | Renumbered |
| 9 | 17b | Merged into Phase 2 "Cross-rule and label dependency analysis" |
| 10 | — | Merged into section 3 (AntiDDoS AMR configuration) |
| 11 | 8 | Renumbered |
| 12 | 18 | Moved to Phase 2 "Rule priority ordering" |
| 13–19 | 9–15 | Renumbered |
| 20 | 16 | Renumbered |

### v0.1

Initial release.

## Disclaimer

This skill is powered by AI, which may produce inaccurate or incomplete findings. The generated report is intended as a starting point for human review — not a substitute for it. Always verify findings against the actual WAF configuration and your business context before making changes.
