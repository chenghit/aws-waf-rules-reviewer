# Handoff: AWS WAF Rules Reviewer v0.3 Optimization

## Project
`~/Documents/github/aws-waf-rules-reviewer` — an Agent Skill that reviews AWS WAF Web ACL configs for security issues.

## Current State
- 6 Python scripts in `scripts/` (preprocess, mermaid, pre-checks, annotate-mermaid, validate-report, generate-report-header)
- 8 knowledge files in `references/` (split from single waf-knowledge.md)
- Trimmed `references/checklist.md` (7KB, down from 22KB)
- SKILL.md has Step 4 split into 9 sub-steps (4.1-4.9) for progressive knowledge loading
- First output latency improved from 10min to 3.5min

## Problem
LLM ignores sub-step instructions — reads ALL knowledge files upfront, then writes all findings at once. This causes:
1. Context bloat (~70KB) leading to slow thinking
2. Unstable quality (15-18 findings per run, some sections skipped)
3. Fixed content (JSON examples, operation steps) unreliably copied by LLM

## Agreed Next Steps (in order)

### 1. Create `waf-generate-appendix.py`
Write ALL fixed content to `{output_dir}/appendix.md`. No conditional logic — always write everything. Only read waf-summary.json for WCU value.

Fixed content blocks:
- A: ASN+UA crawler labeling rule JSON (from crawler-seo.md)
- B: Dual AMR instance 4-step operation + JSON editor instruction (from antiddos-amr.md)
- C: Always-on Challenge two-rule pattern description (from crawler-seo.md)
- D: Recommended Rule Priority Order (from managed-overrides.md)
- E: WCU reminder with current value (from waf-summary.json)
- F: CRS SizeRestrictions_Body reminder

### 2. Remove JSON examples from knowledge files
After extracting to appendix, delete the JSON blocks and fixed operation steps from:
- `references/antiddos-amr.md` (dual instance steps, scope-down JSON)
- `references/crawler-seo.md` (ASN+UA rule JSON, scope-down JSON)
- `references/managed-overrides.md` (priority order list)

### 3. Update SKILL.md
- Add Step 3b: run waf-generate-appendix.py after pre-checks
- Change Step 4 sub-steps: replace "copy JSON into report" with "refer to Appendix X"
- Step 5 (annotate-mermaid) or new step: append appendix.md to report

### 4. Fix waf-pre-checks.py
- Delete wcu_reminder check entirely (WCU goes to appendix)
- Keep challenge_on_post_api and hosting_provider_allow (these are valid structural checks)

### 5. Fix waf-validate-report.py
- Revert wcu_reminder FAIL change (commit 521aff0)
- Rewrite prechecks_coverage: match pre-check FAIL rule names against `**Rule**:` lines in report, instead of keyword matching

### 6. Update waf-annotate-mermaid.py
- After appending Mermaid diagram, also append appendix.md content to report

## Key Decisions Made
- No hard reset — work from current HEAD
- Appendix writes ALL content unconditionally (LLM decides which to reference)
- prechecks_coverage uses `**Rule**:` line matching, not keyword matching
- Section 4/18 further scripting deferred to v0.4
- Python 3.10+ (no 3.8 compat needed)

## Test Data
- `~/tmp/waf-review-report/web-acl-example.json` (27 rules)
- `examples/` in repo has reference output from earlier version
