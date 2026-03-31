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

1. Find the scripts directory. Check these paths in order (stop at first match):
   - `~/.kiro/skills/aws-waf-rules-reviewer/scripts/waf-preprocess.py`
   - `~/.claude/skills/aws-waf-rules-reviewer/scripts/waf-preprocess.py`
   - `~/.codex/skills/aws-waf-rules-reviewer/scripts/waf-preprocess.py`
   - `~/.agents/skills/aws-waf-rules-reviewer/scripts/waf-preprocess.py`
   - `.claude/skills/aws-waf-rules-reviewer/scripts/waf-preprocess.py` (project-level)
   - `.cursor/rules/aws-waf-rules-reviewer/scripts/waf-preprocess.py` (Cursor)
   - `.windsurf/rules/aws-waf-rules-reviewer/scripts/waf-preprocess.py` (Windsurf)
   - `.agents/skills/aws-waf-rules-reviewer/scripts/waf-preprocess.py` (project-level)
   
   Use `fs_read` (directory mode) or a simple `ls` check on each path. If none match, use `glob` with pattern `**/aws-waf-rules-reviewer/scripts/waf-preprocess.py` as a last resort. The parent directory of the found file is `scripts_dir`. If still not found, fall back to the v1 workflow (skip all script steps, do everything manually as described in the "Fallback: Manual Workflow" section at the end).

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

### Step 3b: Generate appendix

```bash
python3 "{scripts_dir}/waf-generate-appendix.py" "{output_dir}"
```

Generates `appendix.md` with fixed reference content (rule JSON templates, implementation steps, priority order table, override recommendations). This file is appended to the final report automatically in Step 5. When your findings recommend these fixed patterns, reference the appendix (e.g., "implementation steps see Appendix B") instead of reproducing the content.

Parse `---RESULT---`. Proceed on OK.

### Step 4: LLM analysis

**CRITICAL: Do NOT delegate Step 4 to a subagent. Perform all analysis yourself in this session.**

Read these files:
- `{output_dir}/waf-summary.json` — structured rule summaries (primary input)
- `{output_dir}/pre-checks.json` — mechanical check results + flags
- [references/checklist.md](references/checklist.md) — review checklist

**Build rule execution flow** from waf-summary.json: walk through all rules in priority order and build a mental model of the request lifecycle. For each rule, note priority, action, labels produced, scope-down conditions, and label dependencies. Map label producers → consumers. Identify Allow rules that terminate evaluation early. This execution flow is your primary analysis tool.

Now run through the checklist in sub-steps. Each sub-step analyzes specific sections, writes findings, then moves on. Number issues sequentially across all sub-steps (#1, #2, #3... continuing from the previous sub-step).

**Step 4.1** — Sections 1, 2 (Allow rules, Scope-down):
- Run through checklist sections 1 and 2 using waf-summary.json and pre-checks.json only.
- For `pre_checks` items with status `FAIL` → adopt the finding directly.
- For `pre_checks` items with status `PASS` → skip.
- For `flags` → use as starting points for reasoning.
- Write findings to `{output_dir}/waf-review-report.md` using `fs_write` `create`. If no findings for these sections, still create the file (write an empty string).

**Step 4.2** — Sections 9, 10, 11, 13, 14, 15 (Missing baseline, WCU, Token domain, Logging, Opaque strings, Default action):
- Run through these checklist sections using waf-summary.json and pre-checks.json only. No knowledge files needed.
- For `pre_checks` items with status `FAIL` → adopt the finding directly.
- For `pre_checks` items with status `PASS` → skip.
- WCU and CRS SizeRestrictions_Body: do NOT write findings for these. They are covered by Appendix E and F.
- Append findings to report using `fs_write` `append`.

**Step 4.3** — Section 3 (AntiDDoS AMR):
- Read `references/antiddos-amr.md`.
- Analyze section 3. Append findings to report using `fs_write` `append`.
- If recommending dual AMR instance: reference Appendix B for implementation steps.
- If recommending crawler exclusion: reference Appendix A for the labeling rule and Appendix B for the scope-down JSON.

**Step 4.4** — Section 4 (Challenge/CAPTCHA applicability):
- Read `references/challenge-captcha.md`.
- Analyze section 4. Append findings.

**Step 4.5** — Section 5 (Bot Control):
- Read `references/bot-control.md`.
- Analyze section 5. Append findings.
- If recommending native app scope-down or SDK integration: include specific rule names and override instructions from the knowledge file. Reference Appendix F for common override recommendations.

**Step 4.6** — Sections 6, 7 (Rate-based, IP reputation):
- Read `references/rate-based.md` and `references/ip-reputation.md`.
- Analyze sections 6 and 7. Append findings.

**Step 4.7** — Sections 8, 16 (Landing page, Always-on Challenge):
- Read `references/crawler-seo.md`.
- Analyze sections 8 and 16. Append findings.
- If recommending a crawler labeling rule: reference Appendix A for the full rule JSON.
- If recommending always-on challenge: reference Appendix C for the two-rule pattern.

**Step 4.8** — Sections 12, 18 (Versions, Priority order):
- Read `references/managed-overrides.md`.
- Analyze sections 12 and 18. Append findings.
- For priority order issues: reference Appendix D for the recommended order.

**Step 4.9** — Section 17 (Cross-rule deps, label analysis):
- Read `references/common-patterns.md`.
- Analyze section 17 using all findings written so far. Append findings.

After all sub-steps, write `{output_dir}/issue-rule-mapping.json`:
```json
{
  "annotations": {
    "AWS-AWSManagedRulesAntiDDoSRuleSet": "⚠️ Issue #2, #8",
    "DSAPP-BYPASS": "⚠️ Issue #1"
  }
}
```
Only include issues that reference an existing rule in the Web ACL. Issues about missing rules (e.g., "No Always-on Challenge rule") or global concerns (e.g., WCU reminder) are NOT included.

**Report format rules (apply to all sub-steps):**
- **Do NOT write a report header or Summary table** — generated by script in Step 4b.
- Each finding: `## Issue N (severity): {title}` format (see "Report Format" below).
- Rule reference lines MUST use: `**Rule**: {name} (priority {N})` or `**Rules**: ...` or `**Rule**: N/A (missing rule)`.
- Cross-references to earlier issues: use issue number. To later issues: use descriptive text.
- End the last Issue section with `---`. Do NOT write a conclusion paragraph.

### Step 4b: Generate report header and Summary table

```bash
python3 "{scripts_dir}/waf-generate-report-header.py" "{output_dir}"
```

Reads Issue sections from the report, extracts severity and title, generates a Summary table (sorted by severity for display), and prepends the report header + Summary table. Parse `---RESULT---`. Proceed on OK.

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
- Verify all checklist sections from Steps 4.1–4.9 were analyzed. If a section was skipped (no finding and no explicit "not applicable"), re-read the relevant knowledge file and evaluate it now.

State: "Self-review completed. Mechanical: {results from validation.json}. Adversarial: {N} re-derived, {N} corrections. Cross-ref: {N} found."

## Key Principles

- **Never assume rules are wrong without understanding intent.** Ask the user about business context before finalizing severity.
- **Evaluate rules as a system, not individually.** Rules interact — fixing one may break another. Always identify cross-rule dependencies.
- **Distinguish DDoS impact from user experience impact.** A rule that's bad for UX but neutral for DDoS is low severity in a DDoS-focused review.
- **Allow is the most dangerous action.** Every Allow rule is a potential bypass. Scrutinize what conditions trigger it and whether those conditions are forgeable.

## Report Format

The LLM writes **only Issue sections** (no header, no Summary table). The header and Summary table are generated by `waf-generate-report-header.py` in Step 4b.

Each Issue section format:

```markdown
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
