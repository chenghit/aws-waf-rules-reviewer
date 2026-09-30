# AWS WAF Rules Reviewer

This repository is a tool for AI agents. After reading this file you can review an AWS WAF Web ACL for security issues, misconfigurations, and optimization opportunities, and write a review report. Nothing needs to be installed.

**When to use it**: the user asks to review, audit, evaluate, or analyze AWS WAF rules or a Web ACL (Chinese: WAF 规则评审、WAF 规则审查、WAF 配置评估、WAF 规则分析). It only covers existing AWS WAF configurations. Don't use it for Cloudflare, other WAF vendors, or migration and conversion work.

**When not to use it**: if the user is changing this repository's own code or docs, treat it as a normal code repo and skip the workflow. See "Maintaining this repository" at the end.

## Language

Reply in the language of the user's message, unless they ask for a specific language. Write the report content in that language too, with one exception: keep the `## Issue N (Severity):` heading prefix, the severity words (Critical, Medium, Low, Awareness), and the `**Rule**:`, `**Rules**:`, `**Current state**:`, `**Problem**:`, and `**Recommendation**:` labels in English. The scripts parse them. The scripted Chinese findings follow the same convention.

## Tools you need

You need to read files, write and append to files, and run shell commands. Use whatever your agent provides for each of these. The steps below say "read", "write", "append", and "run" without naming a specific tool.

Requirements: `python3` 3.10+ (standard library only). On Windows, use `python` or `py -3` if `python3` isn't found. Fetching a Web ACL also needs the AWS CLI with credentials (see Step 0).

## Setup: find `tool_dir`

`tool_dir` is the directory that contains this AGENTS.md. It's the correct one if `{tool_dir}/scripts/waf-preprocess.py` exists.

- You loaded this file from disk, for example because the session runs inside this repo or the user gave you a path. `tool_dir` is that file's directory.
- You read this file from a URL and have no local copy. Clone the repo to a temporary directory and use that:
  ```bash
  git clone --depth 1 https://github.com/chenghit/aws-waf-rules-reviewer.git "${TMPDIR:-/tmp}/aws-waf-rules-reviewer"
  ```
  If that directory already exists, run `git -C "<dir>" pull --ff-only` instead. On Windows, use `%TEMP%`.

All script and reference paths below are relative to `tool_dir`. Resolve every path to an absolute path before running anything.

## Workflow

### Step 0: Get the Web ACL configuration

**Case A: the user gives a file or directory.**

- `input_file` is that path, resolved to an absolute path. If it's a directory, Step 1 finds the WAF JSON inside it.
- `output_dir` is `{parent directory of input_file}/waf-review`. If the directory holds several Web ACL files, review them one at a time and use `{parent directory}/waf-review/{file name without .json}` for each, so the outputs don't overwrite each other.
- If the user also gives the output of `get-logging-configuration`, pass it to Step 1 as `--logging <file>`. Otherwise leave `--logging` out. Logging status then stays unknown.

**Case B: the user has no file.** Fetch the config with the AWS CLI.

Use read-only calls only: `sts get-caller-identity`, `wafv2 list-web-acls`, `wafv2 get-web-acl`, `wafv2 get-logging-configuration`, and in Step 4 `wafv2 get-regex-pattern-set`. Never run `create-*`, `update-*`, `delete-*`, `put-*`, `associate-*`, or any other call that changes state, even if the user asks for a fix during the review. Recommendations belong in the report.

1. Run `aws sts get-caller-identity`. Show the user the account ID and ask them to confirm it's the right account. If the CLI is missing or has no credentials, tell the user and stop. Don't try to set up credentials.
2. Work out the scope and region. CloudFront Web ACLs use `--scope CLOUDFRONT --region us-east-1`. Regional Web ACLs (ALB, API Gateway, AppSync, Cognito, App Runner, Verified Access) use `--scope REGIONAL --region <their region>`. If the user didn't say, ask.
3. List Web ACLs:
   ```bash
   aws wafv2 list-web-acls --scope <SCOPE> --region <REGION>
   ```
   If the response has a `NextMarker`, repeat with `--next-marker <value>` until it doesn't. If there's more than one Web ACL and the user hasn't named one, show the list and ask. Review one Web ACL at a time.
4. Set `output_dir` to `{current working directory}/waf-review/{web_acl_name}` and create it with its `work/` subfolder.
5. Save the Web ACL:
   ```bash
   aws wafv2 get-web-acl --name <NAME> --scope <SCOPE> --id <ID> --region <REGION> > "{output_dir}/work/web-acl.json"
   ```
   `input_file` is `{output_dir}/work/web-acl.json`.
6. Save the logging config, using the Web ACL's `ARN` from the list. A logging config belongs to one log scope, and the call only checks the scope you pass, so try each in turn and stop at the first that succeeds: `CUSTOMER`, `SECURITY_LAKE`, `CLOUDWATCH_TELEMETRY_RULE_MANAGED`.
   ```bash
   aws wafv2 get-logging-configuration --resource-arn <ARN> --log-scope <LOG_SCOPE> --region <REGION> > "{output_dir}/work/logging-configuration.json"
   ```
   - One scope succeeds: pass `--logging "{output_dir}/work/logging-configuration.json"` to Step 1.
   - All three return `WAFNonexistentItemException`: logging isn't enabled. Delete the empty file and pass `--logging none`.
   - Any other error, such as `AccessDeniedException`, or an older CLI that rejects `--log-scope`: delete the empty file, leave `--logging` out, and tell the user logging couldn't be checked.

Example of resolved paths:
```
tool_dir    = /tmp/aws-waf-rules-reviewer
input_file  = /home/user/project/waf-review/prod-acl/work/web-acl.json
output_dir  = /home/user/project/waf-review/prod-acl
```

The report is the only thing at the top of `output_dir`: `waf-review-report.md` and `waf-review-report.html`. The scripts put every intermediate file in `{output_dir}/work/`.

Every script prints a `---RESULT---` block on stdout. Read its `STATUS` line. `OK` means go on. `FATAL` means tell the user what `CONTEXT` says and stop.

### Step 1: Preprocess

```bash
python3 "{tool_dir}/scripts/waf-preprocess.py" "{input_file}" "{output_dir}" [--logging <file>|none]
```

Note the `INPUT_FILE` value. It's the resolved file path, which matters when the user gave a directory. Use it as `input_file` from here on.

### Step 2: Generate base Mermaid diagram

```bash
python3 "{tool_dir}/scripts/waf-generate-mermaid.py" "{output_dir}"
```

### Step 3: Run mechanical pre-checks

```bash
python3 "{tool_dir}/scripts/waf-pre-checks.py" "{output_dir}" "{input_file}"
```

### Step 3b: Generate appendix

Pick `lang` from the user's language: Chinese → `zh`, English → `en`, anything else → `en` (you translate in Step 4). Steps 3b and 3c both take it.

```bash
python3 "{tool_dir}/scripts/waf-generate-appendix.py" "{output_dir}" --lang {lang}
```

This writes `appendix.md` with fixed reference content: rule JSON templates, implementation steps, the priority order table, and override recommendations. Step 5 appends it to the report. Appendix B and C (Anti-DDoS patterns) are left out for a default-Block Web ACL without Anti-DDoS AMR; the other letters don't change. When a finding recommends one of these fixed patterns, point to the appendix (e.g., "implementation steps: see Appendix B") and don't copy the content.

### Step 3c: Generate scripted findings

```bash
python3 "{tool_dir}/scripts/waf-generate-findings.py" "{output_dir}" --lang {lang}
```

This produces the findings a script can fully decide, such as forgeable Allow rules, scope-down problems, ChallengeAllDuringEvent, unanchored regex, missing baseline, token domain, and logging. Outputs:
- `scripted-findings.md`: complete Issue sections in Markdown
- `findings-metadata.json`: includes `llm_sections`, `next_issue_number`, `llm_context`, and `issue_rule_mapping`

### Step 4: LLM analysis

**Do this step yourself in this session. Don't hand it to a subagent.**

Read:
- `{output_dir}/work/scripted-findings.md`
- `{output_dir}/work/findings-metadata.json`
- `{output_dir}/work/waf-summary.json`
- `{tool_dir}/references/checklist.md`

**4.0 Adopt scripted findings.** If `--lang` matches the user's language, write `scripted-findings.md` verbatim to `{output_dir}/waf-review-report.md`. If not, translate it into the user's language and write that instead.

Sanity check: read each scripted finding in full in `scripted-findings.md`, not just its title, and check it against `waf-summary.json`. Scripted findings are deterministic, but they don't know the business context. If one contradicts the summary (e.g., "missing CRS" while CRS is in the rules), or doesn't fit what this Web ACL protects (e.g., recommending Anti-DDoS AMR on an ALB that only accepts CloudFront traffic), remove or rewrite it.

If you remove a scripted finding, renumber the ones after it so the issues run 1, 2, 3 … with no gaps, and update any "Issue N" references in their text. The later scripts read the report itself, so nothing else needs changing.

**4.1+ Analyze the remaining sections.** Analyze only the sections listed in `llm_sections`. Number your findings right after the last scripted finding in the report. That is `next_issue_number` unless you removed some.

First build the rule execution flow from `waf-summary.json`. Walk the rules in priority order. For each rule, note its priority, action, the labels it produces, its scope-down, and the labels it depends on. Map label producers to consumers. Mark the Allow rules that end evaluation early.

For each section in `llm_sections`, read the matching reference file under `{tool_dir}/references/`. Every listed section gets a look, in this order:

- **Section 4** (Challenge and CAPTCHA): read `challenge-captcha.md`. Listed when a rule or override uses Challenge or CAPTCHA. Challenge on POST/API paths and Challenge rate limits are scripted; check the rest: can each target (XHR, API, native app, prefetch) solve it, and what's the immunity time.
- **Section 5** (Bot Control): read `bot-control.md`. Evaluate the Bot Control strategy overall, including Common vs Targeted level and what native apps mean for it. The CategorySearchEngine/CategorySeo Allow finding is already scripted, so don't repeat it. If `llm_context.ua_allow_found` is true, first check what the UA Allow is for. For a native app, analyze what happens to its traffic at Bot Control once that Allow is fixed. For search engine or AI crawlers, the fix is the crawler labeling rule in Appendix A; check which later rules (rate limits, Challenge, geo or IP blocks) the crawlers then hit. Point to Appendix F only for the overrides the Web ACL doesn't have yet.
- **Section 6** (Rate-based rules): read `rate-based.md`. Listed when the Web ACL has rate-based rules. Missing per-IP limits, Challenge rate limits, and shared counts are scripted; check thresholds, which traffic each limit covers, and overlapping scope-downs.
- **Section 7** (IP reputation and anonymous IP): read `ip-reputation.md`. Listed when those groups are present. IP list rules in Count and Security Automations IP sets are scripted; check the groups' scope-downs and whether anything uses their labels (for example `AWSManagedIPDDoSList`).
- **Section 8** (Landing page / cookie logic): read `crawler-seo.md`. Evaluate security decisions based on cookies and whether a WAF token would be a better fit.
- **Section 16** (Always-on Challenge): listed when the scripts found a TARGETED Bot Control with `TGT_TokenAbsent` overridden to Challenge, which challenges token-less requests inside its scope-down, or when a default-Allow Web ACL has no Anti-DDoS AMR. For the first, check whether that scope covers the landing pages, whether the labels it relies on can be forged, and the token immunity time. For the second, decide whether the Web ACL serves browser landing pages that need one. See checklist section 16.
- **Section 17** (Cross-rule dependencies and fix impact): read `common-patterns.md`. 17a (Count rules without labels) is already scripted, so skip it. For 17b, take every fix the report recommends, scripted or yours, and trace the affected traffic through the whole rule chain. Does fix A break rule B or remove a label something relies on? Write down the fix order and which changes must ship together.
- **Section 21** (PCI DSS): decide scope first, using the rule at the top of checklist section 21. It applies to any business that takes card payments, and `llm_context.payment_indicators` lists hosts and paths that look like payment endpoints. If those exist and the user hasn't said, ask. If you can't ask (for example, you're running unattended), write the findings with ` ⏳` instead. If it's in scope, check whether dynamic protections (rate limits, auto-block IP sets, behavior-based bot rules, Challenge) would interfere with ASV scans, and whether long-term Count rules and unknown logging meet Requirement 6.4.2. Recommend confirming with the customer's QSA rather than stating non-compliance.

Append your findings to `waf-review-report.md`.

Report format rules:
- Don't write a report header or Summary table. Step 4b generates them.
- Each finding uses `## Issue N (severity): {title}` (see "Report format" below).
- Start `**Problem**:` and `**Recommendation**:` on their own line, followed by `- ` bullets. The Summary table takes its Impact text from the first Problem bullet. Step 6 checks the severity word, the Rule/Rules form, and the Problem bullets.
- Rule reference lines take one of three forms: `**Rule**: {name} (priority {N})`, `**Rules**: {name} (priority {N}), {name} (priority {N})`, or `**Rule**: N/A (missing rule)`. Only the reason after `N/A` may be in the report's language; `(priority N)` always stays in English. Use `**Rules**:` whenever there's more than one rule. Always write `(priority N)` in full; the validator doesn't read other forms.
- If a finding's severity depends on business context the user has to confirm, append ` ⏳` to the end of its title, never inside the severity brackets: `## Issue 7 (Low): Title ⏳`.
- Refer to scripted findings by issue number. Don't cite the number of a finding you haven't written yet; describe it instead.
- End the last Issue section with `---`. No conclusion paragraph.

Content rules, learned from reviews with customers:
- Say what the configuration does, not what the reader doesn't know. Don't write things like "many customers don't realize".
- Values written into rules (device IDs, test parameters, tokens) are there on purpose, and the Web ACL config isn't public. Judge them by whether a client can send them. Don't call a value leaked or exposed because it's stored in the config.
- Use `capacity` for WCU. Some exports also carry `actual_capacity`, which isn't part of the WAF API; don't cite it.
- `get-web-acl` output has only the ARN of a regex pattern set, not its patterns. If a finding depends on them, fetch the set with `wafv2 get-regex-pattern-set` when you have AWS access (Case B). Otherwise mark the finding ` ⏳` and name the set to check.
- Base claims on the configuration and public AWS documentation. Don't cite internal sources.
- `SizeRestrictions_BODY` in Count is a normal choice: legitimate bodies often exceed 8 KB, and scanners rarely need to. Don't recommend switching it to Block. If the user can list the endpoints that need large bodies, recommend keeping it in Count and adding a custom rule after CRS that blocks its label on all other paths. Never add a scope-down to CRS for this.
- Don't recommend log-driven 4xx auto-blocking for burst scanning. It takes minutes to act and costs a lot to run.
- When discussing Bot Control, state the inspection level the Web ACL actually uses before explaining what it can and can't detect.
- For customers that take card payments, consider PCI DSS: rate limits, auto-block lists, and bot or Challenge rules can interfere with ASV scans (ASV Program Guide section 5.6), and Requirement 6.4.2 expects the WAF to block, or alert with immediate investigation, and to keep audit logs. See `references/checklist.md` section 21.

### Step 4b: Generate report header and Summary table

```bash
python3 "{tool_dir}/scripts/waf-generate-report-header.py" "{output_dir}"
```

### Step 4c: Build issue-rule mapping

```bash
python3 "{tool_dir}/scripts/waf-build-issue-map.py" "{output_dir}"
```

This reads the `**Rule**:` and `**Rules**:` lines of every issue in the report and writes `issue-rule-mapping.json`.

### Step 5: Annotate Mermaid and append to report

```bash
python3 "{tool_dir}/scripts/waf-annotate-mermaid.py" "{output_dir}"
```

### Step 6: Validate report

```bash
python3 "{tool_dir}/scripts/waf-validate-report.py" "{output_dir}" "{input_file}"
```

### Step 7: Self-review

Read `{output_dir}/work/validation.json`.

**Mechanical checks.** If any check is `FAIL`, fix the report and run Step 6 again. Retry at most twice. If it still fails after 3 attempts in total, report the remaining errors to the user and stop. If everything is `PASS`, go on.

**Adversarial check.** This applies only to your own findings, the ones after the last scripted finding. Scripted findings were covered by the sanity check in Step 4.0.
- Take the 2 highest-severity findings you wrote; on a tie, take the lowest issue numbers. Go back to `waf-summary.json`, and to the original JSON via `source.lines` if needed, and derive each one again from scratch. If the new result disagrees with the report, fix the report.
- For each finding that recommends a fix, trace the fix through the rule execution flow. If it breaks another rule or a label dependency, add a note to the finding.

**Cross-reference check.** This covers all findings.
- For each label mentioned in any finding, confirm the producer rule exists and has a lower priority number than the consumer. A label that only a recommended new rule adds (such as `crawler:verified`) is fine; check that the recommendation puts that rule first.
- Check whether any rule in `waf-summary.json` got no finding and no pre-check coverage. If an ignored rule deserves a finding, add it.

If you add or change findings here, put them before the `<!-- waf-appendix:start -->` marker, then run Steps 4b to 6 again. Step 5 replaces the marked appendix block, so running it again doesn't duplicate anything. Put new findings before your fix-order finding (section 17b), renumber that one to come last, and extend it to cover them.

### Step 8: Render HTML

```bash
python3 "{tool_dir}/scripts/waf-render-html.py" "{output_dir}"
```

This writes `waf-review-report.html` next to the Markdown report. It needs no JavaScript and works offline; the rule flow is drawn in HTML, and issue numbers link to their findings. The script checks that every word of the Markdown made it into the HTML. If it returns `FATAL`, tell the user and give only the Markdown path. The Markdown file is the one to edit; after editing it, run this step again.

Then tell the user: "Self-review completed. Mechanical: {passed}/{total} PASS. Adversarial: {N} re-derived, {N} corrections. Cross-ref: {N} label or coverage problems found." Give the report paths `{output_dir}/waf-review-report.html` and `{output_dir}/waf-review-report.md`, and the count of findings per severity. List the findings marked ⏳ that need the user's business context.

## Key principles

- **Don't assume a rule is wrong until you understand its intent.** Ask about business context before settling on severity.
- **Evaluate the rules as a system.** Rules interact, and fixing one can break another. Always look for cross-rule dependencies.
- **Keep DDoS impact apart from user experience impact.** A rule that hurts UX but is neutral for DDoS is low severity in a DDoS-focused review.
- **Allow is the most dangerous action.** Every Allow rule is a possible bypass. Check what triggers it and whether those conditions can be forged.

## Report format

You write only Issue sections. `waf-generate-report-header.py` generates the header and Summary table in Step 4b, and the scripts append the Mermaid diagram in Step 5. Don't draw the diagram yourself.

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

## Severity criteria

- **Critical**: an attacker can bypass the protection entirely, or a core protection mechanism is disabled or ineffective
- **Medium**: a protection gap exists but needs specific conditions to exploit, or a known attack vector isn't blocked
- **Low**: suboptimal configuration with no direct security impact, or a UX or cost issue only
- **Awareness**: not a misconfiguration or vulnerability. It's something the user should know for operations, such as capacity limits, missing observability, stale versions, or behavior that may surprise them during an incident

## Maintaining this repository

- This file is the only workflow definition. There is no SKILL.md or install script. Change the workflow here.
- Scripts use the Python standard library only and follow the `---RESULT---` contract (`SPEC`, `STATUS`, and on failure `ACTION` and `CONTEXT`). `scripts/waf_utils.py` has the shared `fatal()`.
- Finding text lives in `scripts/waf_finding_templates.py`, and short per-item lines live in `LINES` in `scripts/waf-generate-findings.py`. Every key needs both an English and a Chinese version. Findings that list one line per rule start their Problem with a summary line, since the Summary table shows the first Problem bullet.
- `scripts/crawler-uas.json` holds the User-Agents crawler operators publish, with the source for each. Update it when an operator changes its User-Agent, and add only strings from the operator's own documentation.
- Pre-checks read the structured `leaves` that `waf-preprocess.py` records for each statement (field, match type, value, text transformations, fallback, negation), not the summary string. `branches` holds the statement's AND/OR/NOT logic in disjunctive normal form over those leaves; use it when a check depends on how conditions combine, such as whether one forgeable OR branch is enough to trigger an Allow. `SearchString` values are base64-decoded there.
- Test changes on real `get-web-acl` output as well as `examples/`: the example file is plain text in snake_case, while real exports are PascalCase with base64 `SearchString` values.
- `waf-render-html.py` handles the Markdown the reports use. If findings start using other syntax, extend it and compare its output with a CommonMark renderer on real reports.
- Keep `README.md` (Chinese) and `README_EN.md` in sync.
