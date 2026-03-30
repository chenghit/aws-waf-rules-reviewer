---
name: aws-waf-rules-reviewer
description: Review AWS WAF Web ACL rules for security issues, misconfigurations, and optimization opportunities. This skill is exclusively for evaluating existing AWS WAF rule configurations — it does NOT involve Cloudflare, other WAF vendors, or any migration/conversion work. Use when the user asks to review, audit, evaluate, or analyze AWS WAF rules, Web ACL configurations, or WAF JSON exports. Do NOT trigger when the user mentions Cloudflare, migration, conversion, or any non-AWS WAF vendor. Also triggers on Chinese equivalents: WAF 规则评审、WAF 规则审查、WAF 配置评估、WAF 规则分析. Do NOT trigger on: Cloudflare 迁移、WAF 转换、CDN 迁移.
---

# AWS WAF Rules Reviewer

Review AWS WAF Web ACL configurations to identify security issues, misconfigurations, and optimization opportunities.

## Language

**Respond in the same language as the user's message.** If the user explicitly requests a specific language, use that language. The report format below shows placeholder structure — translate all headings, labels, and content to match the output language.

## Workflow

### Step 0: Locate scripts and resolve paths

Before anything else, locate the scripts directory and compute absolute paths.

1. Find the scripts directory. Use `glob` to search for `**/aws-waf-rules-reviewer/scripts/waf-preprocess.py`. The parent directory of the found file is `scripts_dir`. If not found, fall back to the v1 workflow (skip all script steps, do everything manually as described in the "Fallback: Manual Workflow" section at the end).

2. Resolve `input_file`: the user provides a file or directory path. Resolve it to an absolute path.

3. Compute `output_dir`: `{parent directory of input_file}/waf-review` as an absolute path.

All subsequent script commands use these absolute paths. Example:
```
scripts_dir = /home/user/.kiro/skills/aws-waf-rules-reviewer/scripts
input_file  = /home/user/waf-export/waf-rules.json
output_dir  = /home/user/waf-export/waf-review
```

### Step 1: Preprocess

```bash
python3 "{scripts_dir}/waf-preprocess.py" "{input_file}" "{output_dir}"
```

Parse the `---RESULT---` block:
- `STATUS: OK` → proceed. Note the `INPUT_FILE` value (resolved path, useful if user gave a directory).
- `STATUS: FATAL` → report error to user and stop.

### Step 2: Generate base Mermaid diagram

```bash
python3 "{scripts_dir}/waf-generate-mermaid.py" "{output_dir}"
```

Parse `---RESULT---`. Proceed on OK.

### Step 3: Run mechanical pre-checks

```bash
python3 "{scripts_dir}/waf-pre-checks.py" "{output_dir}" "{input_file}"
```

Parse `---RESULT---`. Proceed on OK.

### Step 4: LLM analysis

Read these files:
- `{output_dir}/waf-summary.json` — structured rule summaries (primary input)
- `{output_dir}/pre-checks.json` — mechanical check results + flags
- [references/checklist.md](references/checklist.md) — review checklist
- [references/waf-knowledge.md](references/waf-knowledge.md) — domain knowledge (read sections as referenced by checklist)

**Build rule execution flow** from waf-summary.json: walk through all rules in priority order and build a mental model of the request lifecycle. For each rule, note priority, action, labels produced, scope-down conditions, and label dependencies. Map label producers → consumers. Identify Allow rules that terminate evaluation early. This execution flow is your primary analysis tool.

**Run through the checklist:**
- For `pre_checks` items with status `FAIL` → adopt the finding directly into the report. Verify it makes sense in context, but do not re-derive from scratch.
- For `pre_checks` items with status `PASS` → skip (no finding needed).
- For `flags` → use as starting points for LLM reasoning. The flag provides extracted data; you determine severity and whether it's actually an issue.
- For remaining checklist sections not covered by pre_checks or flags → evaluate using waf-summary.json. If the summary lacks detail for a specific check, use `fs_read` with the `source.lines` from the summary to read the original JSON.

**Write the report** to `{output_dir}/waf-review-report.md`:
- Use `fs_write` `create` for the first write, `append` if needed.
- Report ends with the last Issue section's `---` separator. Do NOT write a conclusion paragraph — the Mermaid appendix will be appended by script in Step 5.
- Report format: see "Report Format" section below.
- Rule reference lines MUST use one of these exact formats:
  - Single rule: `**Rule**: {name} (priority {N})`
  - Multiple rules: `**Rules**: {name1} (priority {N1}), {name2} (priority {N2})`
  - Missing rule: `**Rule**: N/A (missing rule)`

**Write issue-rule-mapping.json** to `{output_dir}/issue-rule-mapping.json`:
```json
{
  "annotations": {
    "AWS-AWSManagedRulesAntiDDoSRuleSet": "⚠️ Issue #2, #8",
    "DSAPP-BYPASS": "⚠️ Issue #1"
  }
}
```
Only include issues that reference an existing rule in the Web ACL. Issues about missing rules (e.g., "No Always-on Challenge rule") or global concerns (e.g., WCU reminder) are NOT included.

### Step 5: Annotate Mermaid and append to report

```bash
python3 "{scripts_dir}/waf-annotate-mermaid.py" "{output_dir}"
```

Parse `---RESULT---`. Proceed on OK.

### Step 6: Validate report

```bash
python3 "{scripts_dir}/waf-validate-report.py" "{output_dir}" "{input_file}"
```

Parse `---RESULT---`. Read `{output_dir}/validation.json`.

### Step 7: Self-review

Read `{output_dir}/validation.json`.

**Mechanical check results** (from validation.json):
- If any check has status `FAIL` → fix the report using `fs_write`, then re-run Step 6. Maximum 2 retries. If validation still fails after 3 total attempts, report remaining errors to the user and stop.
- If all `PASS` → proceed to adversarial check.

**Adversarial check** (assume the report contains errors — your job is to find them):
- Pick the 2 highest-severity findings. Go back to waf-summary.json (and original JSON via `source.lines` if needed) and re-derive each finding independently from scratch. If your re-derivation disagrees with the report, fix it.
- For each finding that recommends a fix, trace the fix through the rule execution flow: does the fix break any other rule or label dependency? If so, add a note to the finding.

**Cross-reference check:**
- For each label mentioned in any finding, verify the producer rule exists and has a lower priority number (higher priority) than the consumer rule.
- Check whether any rules in waf-summary.json were completely ignored (no finding, no pre_check coverage). If an ignored rule deserves a finding, add it.

State: "Self-review completed. Mechanical: {results from validation.json}. Adversarial: {N} re-derived, {N} corrections. Cross-ref: {N} found."

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
```

The Mermaid appendix is generated by scripts and appended automatically in Step 5. Do NOT generate the Mermaid diagram yourself.

## Severity Criteria

- **Critical**: Attackers can bypass the protection entirely, or a core protection mechanism is disabled/ineffective
- **Medium**: Protection gap exists but requires specific conditions to exploit, or a known attack vector is not blocked
- **Low**: Suboptimal configuration that doesn't directly impact security, or UX/cost issue only
- **Awareness**: Not a misconfiguration or vulnerability. Information the user should know for operational awareness — such as capacity limits, missing observability, version staleness, or behaviors that may surprise them during incidents

## Domain Knowledge

Consult [references/waf-knowledge.md](references/waf-knowledge.md) for AWS WAF technical details including:
- Challenge action behavior and limitations
- CAPTCHA action behavior (HTTP 405, token-awareness, difference from Challenge)
- WAF token properties (unforgeability, cookie replacement pattern)
- AntiDDoS AMR mechanics and configuration
- Bot Control Common vs Targeted level, verification mechanism, limitations, and common misconfigurations
- Token labeling behavior
- Rate-based rule characteristics, overlapping scope-down detection, and native app traffic coverage
- IP reputation rule groups (AWSManagedIPDDoSList default Count rationale, relationship with AntiDDoS AMR)
- Anonymous IP rule groups (HostingProviderIPList outdated assumption)
- Always-on Challenge for HTML pages as proactive DDoS defense (only GET + Accept: text/html requests can complete Challenge, so this defense only applies to HTML page requests; scope, immunity time, crawler exclusion)
- ASN + UA crawler labeling rule (Count+Label pattern, JSON example)
- Search engine crawler exclusion pattern (label-based scope-down for AntiDDoS AMR and Always-on Challenge)
- Managed rule group version recommendations (SQLiRuleSet 2.0, BotControlRuleSet 5.0)
- Managed rule group action override mechanics (Count/Allow/Block implications)
- Recommended rule priority order
- WCU capacity limits (5000 per Web ACL)
- CRS SizeRestrictions_Body false positive risk
- KnownBadInputsRuleSet (Log4j, Java deserialization)
- Token domain configuration (apex domain coverage)
- Forgeable vs unforgeable matching conditions
- Count action as a labeling mechanism, its dependencies, and Count-without-labels pitfall
- Common pitfalls and their solutions

## Fallback: Manual Workflow

If scripts are not found in Step 0 (e.g., only SKILL.md and references/ were installed without scripts/), fall back to the original manual workflow:

1. Read the WAF JSON directly (file or directory discovery).
2. Build rule execution flow manually from the JSON.
3. Run through the full checklist manually — all 18 sections, no pre-checks to skip.
4. Generate the complete report including the Mermaid diagram (you must generate it yourself).
5. Self-review: read the saved report and perform all checks manually:
   - Count Summary rows vs Issue sections.
   - Verify rule names and priorities against the JSON.
   - Verify Mermaid diagram completeness.
   - Adversarial check: re-derive the 2 highest-severity findings from scratch.
   - Cross-reference check: verify label dependencies and check for ignored rules.
6. State self-review results.
