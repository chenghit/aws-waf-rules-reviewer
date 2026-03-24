---
name: aws-waf-rules-reviewer
description: Review AWS WAF Web ACL rules for security issues, misconfigurations, and optimization opportunities. This skill is exclusively for evaluating existing AWS WAF rule configurations — it does NOT involve Cloudflare, other WAF vendors, or any migration/conversion work. Use when the user asks to review, audit, evaluate, or analyze AWS WAF rules, Web ACL configurations, or WAF JSON exports. Do NOT trigger when the user mentions Cloudflare, migration, conversion, or any non-AWS WAF vendor. Also triggers on Chinese equivalents: WAF 规则评审、WAF 规则审查、WAF 配置评估、WAF 规则分析. Do NOT trigger on: Cloudflare 迁移、WAF 转换、CDN 迁移.
---

# AWS WAF Rules Reviewer

Review AWS WAF Web ACL configurations to identify security issues, misconfigurations, and optimization opportunities.

## Language

**Respond in the same language as the user's message.** If the user explicitly requests a specific language, use that language. The report format below shows placeholder structure — translate all headings, labels, and content to match the output language.

## Workflow

1. **Locate and read the WAF rules**: The user provides a file path or directory path.
   - If a file path: read it directly
   - If a directory path: look for JSON files containing Web ACL configuration (typically containing `"Rules"` array and `"DefaultAction"` fields). Use `glob` and `grep` to find them.
2. Identify the Web ACL's purpose from context (DDoS protection, bot control, application security, etc.)
3. **Build a rule execution flow**: Before checking individual items, walk through all rules in priority order and build a mental model of the request lifecycle:
   - For each rule, note: priority, action (Allow/Block/Count/Challenge), labels produced, scope-down conditions, and label dependencies
   - Identify which rules are "labeling-only" (Count + add label) vs "terminating" (Allow/Block) vs "conditionally terminating" (Challenge/CAPTCHA — non-terminating for browser HTML requests that can complete the challenge, but effectively Block for non-browser or non-GET requests)
   - Trace how a typical request flows: which rules it hits, which labels accumulate, and where it could be terminated
   - Map label producers → label consumers (e.g., rule at priority 100 adds label X, rule at priority 500 uses label X in scope-down)
   - Identify Allow rules that terminate evaluation early, causing the request to skip all subsequent rules
   This execution flow is your primary analysis tool. Refer back to it when evaluating each checklist item.
4. Run through the checklist in [references/checklist.md](references/checklist.md). When the checklist references a section in waf-knowledge.md, read that section before evaluating the item.
5. For each issue found, assess severity (Critical/Medium/Low/Awareness) based on criteria below
6. **Generate the report**: Write the full report including:
   - Summary table
   - Detailed findings with `⏳ Needs user confirmation` markers where business context is needed
   - **Appendix: Rule Execution Flow** — Mermaid diagram (see Report Format below). This appendix MUST be included in the report.
7. Save the report to the user's specified location. If no location is specified, save it in the same directory as the input WAF rules file, named `waf-review-report.md`.
8. **Self-review (MANDATORY — do not skip)**:
   a. Use `fs_read` to read the saved report file from line 1 to the end. You MUST issue this tool call — do not rely on your memory of what you wrote.
   b. While reading, check for:
      - Issues the checklist missed (rule ordering problems, missing rule groups, cross-rule interactions, domain-specific risks)
      - Inconsistencies between the Summary table and the detailed findings (missing entries, wrong severity, wrong issue numbers)
      - Mermaid diagram correctness (are all rules present? are all label dependencies shown with dashed arrows? are terminating actions branching to terminal nodes? Note: Challenge/CAPTCHA is non-terminating for browser HTML requests that can complete the challenge, but terminating (effectively Block) for non-browser or non-GET requests that cannot complete it — the diagram should reflect both paths)
      - Findings that reference wrong rule names or priority numbers
   c. If you find additional issues or errors, append corrections to the report using `fs_write`.
   d. After completing self-review, state in your response: "Self-review completed. Read {N} lines. Found {N} additional issues / no additional issues."

## Key Principles

- **Never assume rules are wrong without understanding intent.** Ask the user about business context before finalizing severity.
- **Evaluate rules as a system, not individually.** Rules interact — fixing one may break another. Always identify cross-rule dependencies.
- **Distinguish DDoS impact from user experience impact.** A rule that's bad for UX but neutral for DDoS is low severity in a DDoS-focused review.
- **Allow is the most dangerous action.** Every Allow rule is a potential bypass. Scrutinize what conditions trigger it and whether those conditions are forgeable.

## Report Format

```markdown
# AWS WAF Web ACL Rules Review Report

**Web ACL**: {name}
**Review Date**: {date}
**Objective**: {purpose}

## Summary

| Severity | Issue | Impact |
|----------|-------|--------|
| 🔴 Critical | #N {title} | {impact} |
| 🟡 Medium | #N {title} | {impact} |
| 🟢 Low | #N {title} | {impact} |
| 🔵 Awareness | #N {title} | {impact} |

---

## Issue N (severity): {title}

**Rule**: {rule name} (priority N)
**Current state**: {current configuration}

**Problem**:
- {issue description}

**Recommendation**:
- {recommendation}

---

## Appendix: Rule Execution Flow

Generate a Mermaid `flowchart TD` diagram showing the complete rule execution flow. The diagram must include:
- Each rule as a node, labeled with: priority, name, and action
- Solid arrows for request flow (top to bottom in priority order)
- Dashed arrows for label dependencies (from producer rule to consumer rule, annotated with the label name)
- Terminating actions (Allow/Block) branch to a terminal node (✅ Allowed / 🚫 Blocked); Challenge/CAPTCHA on non-browser paths also branch to 🚫 Blocked with a note
- Non-terminating actions (Count, or Challenge with valid token) flow to the next rule
- Diamond shapes for rules with scope-down conditions
- Key overrides noted inline on managed rule group nodes (e.g., "ChallengeAllDuringEvent→Count")
- Issue references on affected nodes (e.g., "⚠️ Issue #4")
- Final node showing the default action for unmatched requests

Wrap the diagram in a ` ```mermaid ` code block so it renders in GitHub, VS Code, Typora, etc.

```

## Severity Criteria

- **Critical**: Attackers can bypass the protection entirely, or a core protection mechanism is disabled/ineffective
- **Medium**: Protection gap exists but requires specific conditions to exploit, or a known attack vector is not blocked
- **Low**: Suboptimal configuration that doesn't directly impact security, or UX/cost issue only
- **Awareness**: Not a misconfiguration or vulnerability. Information the user should know for operational awareness — such as capacity limits, missing observability, version staleness, or behaviors that may surprise them during incidents

## Domain Knowledge

Consult [references/waf-knowledge.md](references/waf-knowledge.md) for AWS WAF technical details including:
- Challenge action behavior and limitations
- AntiDDoS AMR mechanics and configuration
- Bot Control Common vs Targeted level, verification mechanism, limitations, and common misconfigurations
- Token labeling behavior
- Rate-based rule characteristics and overlapping scope-down detection
- IP reputation rule groups (AWSManagedIPDDoSList default Count rationale, relationship with AntiDDoS AMR)
- Anonymous IP rule groups (HostingProviderIPList outdated assumption)
- Always-on Challenge for HTML pages as proactive DDoS defense (only GET + Accept: text/html requests can complete Challenge, so this defense only applies to HTML page requests; scope, immunity time, crawler exclusion)
- ASN + UA crawler labeling rule (Count+Label pattern, JSON example)
- Search engine crawler exclusion pattern (label-based scope-down for AntiDDoS AMR and Always-on Challenge)
- Managed rule group action override mechanics (Count/Allow/Block implications)
- Recommended rule priority order
- CRS SizeRestrictions_Body false positive risk
- Token domain configuration (apex domain coverage)
- Count action as a labeling mechanism and its dependencies
- Common pitfalls and their solutions
