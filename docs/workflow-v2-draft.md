# SKILL.md Workflow v2 Draft (revised)

Design draft for the new workflow with preprocessing scripts.

## Design Decisions

- **No subagent**: SKILL.md guides the current agent to run scripts + do LLM reasoning
- **Scripts location**: `~/.kiro/skills/aws-waf-rules-reviewer/scripts/`
- **Data files**: `~/.kiro/skills/aws-waf-rules-reviewer/scripts/managed-labels.json`
- **Output directory**: `{input_json_parent}/waf-review/` (fallback to CWD if no write permission)
- **All paths absolute**: SKILL.md instructs LLM to compute absolute output_dir first, all script calls use it
- **execute_bash**: Required for running scripts. Some agents may prompt user for authorization.
- **Python 3.8+, stdlib only**: No pip install required
- **SCRIPT_STANDARDS compliant**: All scripts output `---RESULT---` block on stdout

## File Flow

See [waf-summary-schema.md](waf-summary-schema.md) for the complete waf-summary.json schema.

```
Input:  {input_path} (user-provided file or directory)

Preparation: LLM computes absolute paths
  input_file = resolved absolute path to the WAF JSON file
  output_dir = {input_file_parent}/waf-review   (fallback: {cwd}/waf-review)

Step 1: waf-preprocess.py "{input_file}" "{output_dir}"
  → {output_dir}/waf-summary.json

Step 2: waf-generate-mermaid.py "{output_dir}"
  → {output_dir}/mermaid-base.md
  → {output_dir}/mermaid-metadata.json

Step 3: waf-pre-checks.py "{output_dir}" "{input_file}"
  → {output_dir}/pre-checks.json

Step 4: LLM analysis
  reads: waf-summary.json, pre-checks.json, checklist.md, waf-knowledge.md
  writes: {output_dir}/waf-review-report.md (without Mermaid appendix)
          {output_dir}/issue-rule-mapping.json

Step 5: waf-annotate-mermaid.py "{output_dir}"
  reads: mermaid-base.md, mermaid-metadata.json, issue-rule-mapping.json
  → {output_dir}/mermaid-final.md
  → appends Mermaid appendix to waf-review-report.md

Step 6: waf-validate-report.py "{output_dir}" "{input_file}"
  reads: waf-review-report.md, waf-summary.json, mermaid-metadata.json
  → {output_dir}/validation.json

Step 7: LLM self-review (adversarial + cross-reference, guided by validation.json)
  → fixes to waf-review-report.md if needed
```

## New Workflow Detail

### Preparation: Resolve paths

Before running any script, compute:
1. `input_file`: If user provided a file path, resolve to absolute. If user provided
   a directory, the preprocess script will find the JSON file (see Step 1).
2. `output_dir`: `{parent_of_input_file}/waf-review` as absolute path.

### Step 1: Preprocess

```bash
python3 ~/.kiro/skills/aws-waf-rules-reviewer/scripts/waf-preprocess.py "{input_path}" "{output_dir}"
```

Input path can be a file or directory:
- File: use directly
- Directory: script finds JSON files containing Web ACL structure. If 0 found → error.
  If 1 found → use it. If >1 found → error listing all candidates.

Script handles three JSON formats:
- AWS CLI: `{"WebACL": {"Rules": [...]}, "LockToken": "..."}`
- Console export: `{"Rules": [...], "DefaultAction": {...}}`
- Non-standard snake_case: `{"web_acl": {"rules": [...]}}`

Parse the `---RESULT---` block:
- `STATUS: OK` → read `OUTPUT_FILE` to get waf-summary.json path. Update `input_file`
  from `INPUT_FILE` field (resolved by script in directory mode). Proceed.
- `STATUS: ERROR` or `STATUS: FATAL` → report error to user and stop.

### Step 2: Generate base Mermaid diagram

```bash
python3 ~/.kiro/skills/aws-waf-rules-reviewer/scripts/waf-generate-mermaid.py "{output_dir}"
```

Reads waf-summary.json + managed-labels.json (bundled with scripts).
Generates:
- mermaid-base.md: diagram without issue annotations
  - ≤25 rules: detailed mode (every rule = one node)
  - >25 rules: grouped mode (consecutive same-type managed rule groups and
    consecutive rate-based rules folded; Allow rules, label-dependent rules always expanded)
- mermaid-metadata.json: node list, label dependencies, fold groups (for validation + annotation)

Parse `---RESULT---` block. Proceed on OK.

### Step 3: Run mechanical pre-checks

```bash
python3 ~/.kiro/skills/aws-waf-rules-reviewer/scripts/waf-pre-checks.py "{output_dir}" "{input_file}"
```

Reads waf-summary.json + original JSON.
Generates pre-checks.json:

```json
{
  "pre_checks": {
    "token_domain": {"status": "PASS|FAIL", "finding": "..."},
    "managed_versions": {"status": "PASS|FAIL", "finding": "..."},
    "default_action_redundancy": {"status": "PASS|FAIL", "finding": "..."},
    "count_without_labels": {"status": "PASS|FAIL", "rules": [...]},
    "wcu_reminder": {"status": "INFO", "finding": "..."}
  },
  "flags": {
    "allow_rules": [
      {
        "name": "...", "priority": N,
        "forgeable_conditions": ["single_header:user-agent"],
        "unforgeable_conditions": [],
        "all_forgeable": true,
        "blast_radius": "global | path_scoped"
      }
    ],
    "scope_downs": [
      {"rule": "...", "scope_down_summary": "URI EXACTLY '/'"}
    ],
    "exempt_regex_branches": [
      {"rule": "...", "branches": [{"pattern": "...", "anchored_start": false, "anchored_end": false}]}
    ]
  }
}
```

Parse `---RESULT---` block. Proceed on OK.

### Step 4: LLM analysis

Read these files:
- `{output_dir}/waf-summary.json`
- `{output_dir}/pre-checks.json`
- `references/checklist.md`
- `references/waf-knowledge.md` (read sections as referenced by checklist)

**Build rule execution flow** from waf-summary.json (same mental model as v1 workflow).

**Run through checklist:**
- pre_checks items with FAIL → adopt finding into report (verify it makes sense, don't re-derive)
- pre_checks items with PASS → skip
- flags → use as starting points for LLM reasoning (flag = extracted data, LLM determines severity)
- Remaining checklist sections → evaluate using waf-summary.json. If summary lacks detail,
  use `fs_read(start_line=X, end_line=Y)` on the original JSON at the source_lines from summary.

**Write the report** to `{output_dir}/waf-review-report.md`:
- Use `fs_write` `create` for the first write, `append` if needed
- Report ends with the last Issue section's `---` separator. Do NOT write a conclusion or summary paragraph after the last issue — the Mermaid appendix will be appended by script in Step 5.
- Report format is the same as v1 (Summary table + Issue sections)

**Write issue-rule-mapping.json** to `{output_dir}/issue-rule-mapping.json`:
```json
{
  "annotations": {
    "AWS-AWSManagedRulesAntiDDoSRuleSet": "⚠️ Issue #2, #8",
    "DSAPP-BYPASS": "⚠️ Issue #1"
  }
}
```
Only include issues that reference an existing rule in the Web ACL. Issues about
missing rules (e.g., "No Always-on Challenge rule") or global concerns (e.g., WCU
reminder) are NOT included — they have no corresponding node in the Mermaid diagram.

### Step 5: Annotate Mermaid and append to report

```bash
python3 ~/.kiro/skills/aws-waf-rules-reviewer/scripts/waf-annotate-mermaid.py "{output_dir}"
```

- Reads mermaid-base.md + issue-rule-mapping.json + mermaid-metadata.json
- Adds issue annotations to affected nodes
- If an annotated rule is inside a fold group (grouped mode), expands that group
- Appends `## Appendix: Rule Execution Flow` + mermaid code block to waf-review-report.md

Parse `---RESULT---` block. Proceed on OK.

### Step 6: Validate report

```bash
python3 ~/.kiro/skills/aws-waf-rules-reviewer/scripts/waf-validate-report.py "{output_dir}" "{input_file}"
```

Mechanical checks:
- Summary table row count == `## Issue` section count
- Each Summary row matches its Issue section (number, severity, title)
- Rule names and priorities in findings exist in waf-summary.json
- Mermaid node count >= rule count (from mermaid-metadata.json; >= because terminal nodes add extra)

Outputs validation.json:
```json
{
  "summary_issue_count": {"status": "PASS", "summary_rows": 18, "issue_sections": 18},
  "summary_detail_match": {"status": "PASS", "mismatches": []},
  "rule_references": {"status": "PASS", "invalid_refs": []},
  "mermaid_completeness": {"status": "PASS", "missing_rules": []}
}
```

### Step 7: LLM self-review

Read `{output_dir}/validation.json`.

**Mechanical check results:**
- If any check has status FAIL → fix the report, then re-run Step 6. Maximum 2 retries.
  If validation still fails after 3 total attempts, report the remaining errors to the
  user and stop: "Report validation failed after 3 attempts. Remaining issues: {errors}"
- If all PASS → proceed to adversarial check.

**Adversarial check:**
- Pick the 2 highest-severity findings
- Go back to waf-summary.json (and original JSON via source_lines if needed)
- Re-derive each finding independently from scratch
- If re-derivation disagrees → fix the report

**Cross-reference check:**
- For each label in any finding, verify producer rule exists with lower priority than consumer
- Check if any rules in waf-summary.json were completely ignored (no finding, no pre_check coverage)
- If ignored rule deserves a finding, add it

State: "Self-review completed. Mechanical: {results from validation.json}.
Adversarial: {N} re-derived, {N} corrections. Cross-ref: {N} found."

## Script Interface Summary

| Script | Args | Key Output | RESULT fields |
|--------|------|------------|---------------|
| waf-preprocess.py | input_path, output_dir | waf-summary.json | STATUS, OUTPUT_FILE, INPUT_FILE, RULE_COUNT |
| waf-generate-mermaid.py | output_dir | mermaid-base.md, mermaid-metadata.json | STATUS, MODE (detailed/grouped), NODE_COUNT |
| waf-pre-checks.py | output_dir, input_file | pre-checks.json | STATUS, CHECKS_RUN, CHECKS_FAILED |
| waf-annotate-mermaid.py | output_dir | mermaid-final.md (appended to report) | STATUS, ANNOTATIONS_APPLIED |
| waf-validate-report.py | output_dir, input_file | validation.json | STATUS, CHECKS_PASSED, CHECKS_FAILED |

## Data Files

`~/.kiro/skills/aws-waf-rules-reviewer/scripts/managed-labels.json`:
```json
{
  "label_producers": {
    "AWSManagedRulesAntiDDoSRuleSet": [
      "awswaf:managed:aws:anti-ddos:challengeable-request",
      "awswaf:managed:aws:anti-ddos:event-detected",
      "awswaf:managed:aws:anti-ddos:ddos-request",
      "awswaf:managed:aws:anti-ddos:high-suspicion-ddos-request",
      "awswaf:managed:aws:anti-ddos:medium-suspicion-ddos-request",
      "awswaf:managed:aws:anti-ddos:low-suspicion-ddos-request",
      "awswaf:managed:aws:anti-ddos:ChallengeAllDuringEvent",
      "awswaf:managed:aws:anti-ddos:ChallengeDDoSRequests",
      "awswaf:managed:aws:anti-ddos:DDoSRequests"
    ],
    "AWSManagedRulesAmazonIpReputationList": [
      "awswaf:managed:aws:amazon-ip-list:AWSManagedIPReputationList",
      "awswaf:managed:aws:amazon-ip-list:AWSManagedReconnaissanceList",
      "awswaf:managed:aws:amazon-ip-list:AWSManagedIPDDoSList"
    ],
    "AWSManagedRulesAnonymousIpList": [
      "awswaf:managed:aws:anonymous-ip-list:AnonymousIPList",
      "awswaf:managed:aws:anonymous-ip-list:HostingProviderIPList"
    ],
    "AWSManagedRulesBotControlRuleSet": [
      "awswaf:managed:aws:bot-control:bot:verified",
      "awswaf:managed:aws:bot-control:bot:unverified",
      "awswaf:managed:aws:bot-control:signal:non_browser_user_agent",
      "awswaf:managed:aws:bot-control:bot:category:{category}",
      "awswaf:managed:aws:bot-control:bot:name:{name}"
    ]
  },
  "shared_token_labels": [
    "awswaf:managed:token:absent",
    "awswaf:managed:token:accepted",
    "awswaf:managed:token:rejected",
    "awswaf:managed:token:rejected:expired",
    "awswaf:managed:token:rejected:domain_mismatch",
    "awswaf:managed:token:rejected:not_solved",
    "awswaf:managed:token:rejected:invalid",
    "awswaf:managed:captcha:absent",
    "awswaf:managed:captcha:accepted",
    "awswaf:managed:captcha:rejected"
  ],
  "token_label_producers": [
    "AWSManagedRulesAntiDDoSRuleSet",
    "AWSManagedRulesBotControlRuleSet",
    "AWSManagedRulesATPRuleSet",
    "AWSManagedRulesACFPRuleSet"
  ],
  "forgeability": {
    "forgeable_field_types": [
      "single_header", "single_query_argument", "cookie", "cookies",
      "body", "json_body", "uri_path", "query_string", "method",
      "header_order", "headers"
    ],
    "unforgeable_statement_types": [
      "ip_set_reference_statement", "asn_match_statement",
      "geo_match_statement", "rate_based_statement"
    ],
    "unforgeable_field_types": [
      "ja3_fingerprint", "ja4_fingerprint"
    ]
  }
}
```

Note: Bot Control category/name labels use `{category}` and `{name}` as patterns.
The Mermaid script matches label_match_statement values against these patterns using
prefix matching (e.g., any label starting with `awswaf:managed:aws:bot-control:bot:category:`
is attributed to Bot Control). Individual category labels (700+) are NOT enumerated.

CRS, KnownBadInputs, SQLi, and other application-layer rule groups are intentionally
not listed. Their labels are rarely consumed by custom rules. If a custom rule does
reference their labels, the reverse-discovery mechanism in waf-generate-mermaid.py
will find the dependency from label_match_statement in the JSON.

## Installation Changes

```
~/.kiro/skills/aws-waf-rules-reviewer/
├── SKILL.md
├── references/
│   ├── checklist.md
│   └── waf-knowledge.md
└── scripts/
    ├── managed-labels.json
    ├── waf-preprocess.py
    ├── waf-generate-mermaid.py
    ├── waf-pre-checks.py
    ├── waf-annotate-mermaid.py
    └── waf-validate-report.py
```

install.sh / install.bat need to copy scripts/ directory.

## Open Questions (resolved)

1. ~~Output directory~~ → input JSON parent dir, fallback CWD on permission error
2. ~~Single vs multi write~~ → create + append fallback (keep from v1)
3. ~~Python version~~ → 3.8+, stdlib only
