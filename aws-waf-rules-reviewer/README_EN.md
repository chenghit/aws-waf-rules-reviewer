# AWS WAF Rules Reviewer

[中文版](README.md)

An [Agent Skill](https://agentskills.io) that reviews AWS WAF Web ACL configurations for security issues, misconfigurations, and optimization opportunities.

## What It Does

Given an AWS WAF Web ACL JSON export, this skill:

1. Builds a rule execution flow — mapping every rule's priority, action, labels, and dependencies
2. Runs through a 20-item checklist covering Allow rule audits, scope-down validation, AntiDDoS AMR configuration, Bot Control settings, SEO impact, rate limiting, cross-rule dependencies, and more
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

The review covers 20 categories:

1. Allow rules audit (forgeability, bypass risk)
2. Scope-down statements (too narrow / too broad)
3. AntiDDoS AMR configuration (ChallengeAllDuringEvent, exempt regex, SEO impact)
4. Challenge action applicability (POST/API/native app limitations)
5. Bot Control configuration (Allow override risks, verified vs unverified bots)
6. Token and label dependencies (label source correctness)
7. Rate-based rules (activation delay, threshold reasonableness)
8. IP reputation and anonymous IP rules
9. Cross-rule dependency analysis (fix ordering, label chain breaks)
10. Dual AMR instance pattern
11. Landing page and cookie-based logic
12. Rule priority ordering (label producers before consumers)
13. Missing baseline protections (CRS, KnownBadInputs)
14. WCU capacity awareness
15. Token domain configuration
16. Managed rule group versions
17. Logging and monitoring
18. Hashed/opaque search_string in byte_match_statement
19. Default action (redundant trailing Allow-all detection)
20. Always-on Challenge for HTML pages (proactive DDoS defense, immunity time, crawler exclusion)

## Disclaimer

This skill is powered by AI, which may produce inaccurate or incomplete findings. The generated report is intended as a starting point for human review — not a substitute for it. Always verify findings against the actual WAF configuration and your business context before making changes.
