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

1. Find the scripts directory. Use `fs_read` in Line mode to check if the file exists. Check these paths in order (stop at first match):
   ```
   ~/.kiro/skills/aws-waf-rules-reviewer/scripts/waf-preprocess.py
   ~/.claude/skills/aws-waf-rules-reviewer/scripts/waf-preprocess.py
   ~/.codex/skills/aws-waf-rules-reviewer/scripts/waf-preprocess.py
   ~/.agents/skills/aws-waf-rules-reviewer/scripts/waf-preprocess.py
   .claude/skills/aws-waf-rules-reviewer/scripts/waf-preprocess.py
   .cursor/rules/aws-waf-rules-reviewer/scripts/waf-preprocess.py
   .windsurf/rules/aws-waf-rules-reviewer/scripts/waf-preprocess.py
   .agents/skills/aws-waf-rules-reviewer/scripts/waf-preprocess.py
   ```
   
   **IMPORTANT**: Use `fs_read` (Line mode, start_line=1, end_line=1) to probe each path. `fs_read` supports `~` for home directory. Do NOT use `glob` for absolute paths — `glob` only searches relative to the current working directory. If none of the above paths exist, use `glob` with pattern `**/aws-waf-rules-reviewer/scripts/waf-preprocess.py` as a last resort (this only finds project-level installs). The parent directory of the found file is `scripts_dir`.

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

### Step 3c: Generate scripted findings

Determine the `--lang` flag from the user's language:
- Chinese → `--lang zh`
- English → `--lang en`
- Other → `--lang en` (you will translate scripted findings in Step 4)

```bash
python3 "{scripts_dir}/waf-generate-findings.py" "{output_dir}" --lang {lang}
```

Generates deterministic findings for checklist sections that can be fully evaluated by script (forgeable Allow rules, scope-down issues, ChallengeAllDuringEvent, unanchored regex, missing baseline, token domain, etc.). Outputs:
- `scripted-findings.md` — complete Issue section Markdown
- `findings-metadata.json` — structured metadata including `llm_sections`, `next_issue_number`, and `issue_rule_mapping`

Parse `---RESULT---`. Proceed on OK.

### Step 4: LLM analysis

**CRITICAL: Do NOT delegate Step 4 to a subagent. Perform all analysis yourself in this session.**

Read these files:
- `{output_dir}/scripted-findings.md` — scripted findings (primary input for the report)
- `{output_dir}/findings-metadata.json` — metadata: `llm_sections`, `next_issue_number`, `llm_context`
- `{output_dir}/waf-summary.json` — structured rule summaries
- [references/checklist.md](references/checklist.md) — review checklist

**Step 4.0: Adopt scripted findings**

If `--lang` matches the user's language, copy `scripted-findings.md` content into `{output_dir}/waf-review-report.md` verbatim using `fs_write` `create`.

If the user's language is not en/zh (i.e., `--lang en` was used as fallback), translate the scripted findings into the user's language and write the translated version.

**Sanity check**: Scan `findings-metadata.json` scripted issues against `waf-summary.json`. If any scripted finding contradicts the summary (e.g., "missing CRS" but CRS is present in rules), flag it and override — remove or rewrite that finding.

**Step 4.1+: Analyze remaining sections**

Read `llm_sections` from `findings-metadata.json`. Only analyze the sections listed there. Number your findings starting from `next_issue_number`.

**Build rule execution flow** from waf-summary.json: walk through all rules in priority order and build a mental model of the request lifecycle. For each rule, note priority, action, labels produced, scope-down conditions, and label dependencies. Map label producers → consumers. Identify Allow rules that terminate evaluation early.

For each section in `llm_sections`, read the relevant reference file and analyze:

- **Section 5** (Bot Control): Read `references/bot-control.md`. Evaluate overall Bot Control strategy (Common vs Targeted level, native app implications). The CategorySearchEngine/CategorySeo Allow finding is already scripted — do not duplicate it. If a forgeable UA-based Allow rule was found (check `llm_context.ua_allow_found`), analyze the native app → Bot Control implication. Reference Appendix F for common override recommendations.
- **Section 8** (Landing page / cookie logic): Read `references/crawler-seo.md`. Evaluate cookie-based security decisions, WAF token alternatives.
- **Section 17** (Cross-rule deps + fix impact): Read `references/common-patterns.md`. Section 17a (Count rules without labels) is already scripted — skip it. Only analyze 17b: for each fix recommended in the report (both scripted and your own), trace affected traffic through the full rule chain. Does fix A break rule B? Remove a label? Document recommended fix order and simultaneous changes needed.

Append your findings to the report using `fs_write` `append`.

**Report format rules:**
- **Do NOT write a report header or Summary table** — generated by script in Step 4b.
- Each finding: `## Issue N (severity): {title}` format (see "Report Format" below).
- Rule reference lines MUST use: `**Rule**: {name} (priority {N})` or `**Rules**: ...` or `**Rule**: N/A (missing rule)`.
- Cross-references to scripted findings: use their issue number. To later issues: use descriptive text.
- End the last Issue section with `---`. Do NOT write a conclusion paragraph.

### Step 4b: Generate report header and Summary table

```bash
python3 "{scripts_dir}/waf-generate-report-header.py" "{output_dir}"
```

Reads Issue sections from the report, extracts severity and title, generates a Summary table (sorted by severity for display), and prepends the report header + Summary table. Parse `---RESULT---`. Proceed on OK.

### Step 4c: Build issue-rule mapping

```bash
python3 "{scripts_dir}/waf-build-issue-map.py" "{output_dir}"
```

Merges scripted findings' rule mappings (from `findings-metadata.json`) with LLM findings' `**Rule**:` lines to produce `issue-rule-mapping.json`. Parse `---RESULT---`. Proceed on OK.

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

**Adversarial check** (only for LLM-generated findings — scripted findings are deterministic and do not need re-derivation):
- Pick the 2 highest-severity LLM-generated findings (issue numbers ≥ `next_issue_number`). Go back to waf-summary.json (and original JSON via `source.lines` if needed) and re-derive each finding independently from scratch. If your re-derivation disagrees with the report, fix it.
- For each finding that recommends a fix, trace the fix through the rule execution flow: does the fix break any other rule or label dependency? If so, add a note to the finding.

**Cross-reference check** (covers all findings — both scripted and LLM):
- For each label mentioned in any finding, verify the producer rule exists and has a lower priority number (higher priority) than the consumer rule.
- Check whether any rules in waf-summary.json were completely ignored (no finding, no pre_check coverage). If an ignored rule deserves a finding, add it.

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
