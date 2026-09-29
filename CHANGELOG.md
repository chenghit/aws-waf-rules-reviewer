# Changelog

## v0.7.2 (2026-09-29)

### Fixed
- The CRS rule name is `SizeRestrictions_BODY`. Scripts and references wrote `SizeRestrictions_Body` in six places.
- The ordering check counts managed rule groups with a rule overridden to Allow as Allow sources. A block list after `HostingProviderIPList → Allow` is now reported.
- AGENTS.md has instructions for section 16, which v0.7.1 started handing to the LLM. It says that only the reason after `N/A` may be translated, never `(priority N)`, and that PCI scope questions become ` ⏳` findings when the agent can't ask the user.

## v0.7.1 (2026-09-29)

Fixes from regenerating the example with v0.7.

### Fixed
- Scripted findings assumed `ChallengeAllDuringEvent` was on. The exempt-regex finding now names the Challenge rule that actually skips exempt paths, drops to Low when neither Challenge rule acts, and is skipped when Challenge is disabled. The crawler labeling finding is Low while `ChallengeAllDuringEvent` is in Count. Both read the rule group state through one helper.
- The exempt-regex fix now warns that adding `^` breaks branches for APIs under a prefix such as `/v1/`.
- A TARGETED Bot Control with `TGT_TokenAbsent` overridden to Challenge counts as an always-on Challenge for its scope. The "missing Always-on Challenge" finding goes to the LLM instead of being reported as missing.
- The Bot Control version finding no longer says "COMMON level" for a TARGETED rule group.
- `waf-summary.json` keeps the match scope and pattern for Cookies, Headers, and JsonBody, e.g. `cookies[scope=KEY, included=ab_session_id, oversize=MATCH]`. Before, a cookie name match read like a value match.
- Scripted findings use `**Rules**:` for more than one rule, and no longer join rules with "and".
- The report header and Summary table are in Chinese for `--lang zh`.
- No second horizontal rule before the appendix, and a blank line before `---` in the missing-baseline finding.
- Em dashes removed from finding templates and the appendix.

### Added
- Validation check `issue_format`. It fails a report whose severity isn't exactly Critical, Medium, Low, or Awareness (for example `(Low ⏳)`), that lists several rules under `**Rule**:`, or whose `**Problem**:` isn't followed by bullets.

## v0.7 (2026-09-29)

### Changed
- The output folder holds only the report: `waf-review-report.md` and `waf-review-report.html`. Every intermediate file, including `web-acl.json` and `logging-configuration.json` fetched in Case B, now goes in `work/`. Scripts resolve these paths through `work_path()` in `waf_utils.py`.

### Added
- `waf-render-html.py` (Step 8) turns the Markdown report into one self-contained HTML file. The rule flow is drawn with HTML and CSS instead of Mermaid, so the file needs no JavaScript and works offline; each rule card shows its action, overrides, scope-down, labels, and links to its issues. The example report is 56 KB. Inlining `mermaid.min.js` would have added 3.6 MB to every report.
- The script checks that every word of the Markdown made it into the HTML and that every rule appears in the flow, and returns `FATAL` otherwise. Tested against markdown-it (CommonMark with tables) on 34 scripted reports and 17 LLM-written reports: identical structure and text, except where the renderer keeps text that CommonMark would drop or turn into emphasis, such as `Category_*/Signal_*`, an extra table cell, or an ordered list that starts right after a paragraph.

## v0.6.1 (2026-09-29)

Fixes found by regenerating the example report with v0.6.

### Fixed
- Anti-DDoS AMR settings in real `get-web-acl` exports were never read. The preprocessor only understood a flat config format, so on real exports the exempt-regex check and the challenge sensitivity were silently skipped. It now also reads `ClientSideActionConfig.Challenge`, and the exempt-regex check covers every regex object, not only the first.
- The Summary table could show the next issue's text as a finding's Impact when the finding's Problem section didn't start with a bullet. Impact is now taken from the issue's own section only.
- The IP block list ordering check missed block lists written as `AND(ip_set, host)`. It now accepts host conditions alongside the IP set, but not `OR` or negated conditions.
- `HostingProviderIPList` overridden to Allow is Medium, not Critical, when the rule group's scope-down limits it to certain paths. The finding says which requests the Allow applies to and warns to change the override before widening the scope-down.
- The `ChallengeAllDuringEvent` finding said low-suspicion traffic got no soft mitigation, even when `ChallengeDDoSRequests` was still challenging it. It now reads both challenge rules and the block and challenge sensitivities, and names the suspicion levels that get neither Challenge nor Block. It's Medium only when such a level exists, Low otherwise.
- The Bot Control version finding listed 2.0/3.0 changes to a Web ACL pinned at 4.0, and credited 2.0/3.0 with rules they didn't add. It now lists only the versions after the current one, using the AWS Managed Rules changelog.
- `--lang zh` output no longer contains English fragments (forgeable Allow examples, opaque-value notes, Allow override details, AMR sensitivity text). The appendix and the Mermaid appendix heading are in Chinese too.
- `references/bot-control.md` and the checklist said never to override `TGT_TokenAbsent` to Count. Its default is Count, so that override changes nothing. The text now says to keep a Challenge override if the Web ACL has one.
- The exempt-regex bypass example no longer shows a double slash (`/admin/api//export`).

### Changed
- Duplicate detection covers every rule type, not only rate-based rules, and groups of more than two. It compares the whole rule except name and priority, and the finding is Low. The forgeable Allow and Count-without-labels findings no longer guess that their rules might be duplicates.
- Checklist section 21 (PCI DSS) applies to any business that takes card payments. `findings-metadata.json` has a new `llm_context.payment_indicators` list of hosts and paths that look like payment endpoints. If the list isn't empty and the user hasn't said whether the systems are in PCI scope, the agent asks.
- `waf-generate-appendix.py` takes `--lang`. AGENTS.md picks the language before Step 3b.
- AGENTS.md requires `**Problem**:` and `**Recommendation**:` to be followed by `- ` bullets.

## v0.6 (2026-09-29)

Findings from reviewing 16 production Web ACLs exported with `get-web-acl`.

### Fixed
- `waf-preprocess.py` now base64-decodes ByteMatch `SearchString` values. Real exports store them base64-encoded, so every path-based check was comparing encoded strings, and the opaque-value check reported ordinary paths such as `/risk-center` as possible secrets.
- Key normalization turned `UriPath` into `uripath` (the `i_p` → `ip` fix matched inside words), so no check recognized URI path conditions in PascalCase exports. Fixes now apply to whole segments only.
- Managed version check skipped rule groups with no `VersionToUse`. It now reports unpinned groups, and Bot Control on the default Version_1.0 or below 5.0 as Medium. The "SQLi below 2.0" rule is gone: SQLi has two version lineages, so a lower number isn't an older detection.
- Count-without-labels check now covers rate-based rules.
- Appendix no longer contains literal `{{ }}`.
- `waf-annotate-mermaid.py` replaces a marked appendix block instead of appending, so re-running it is safe, and it appends the appendix even when there are no annotations.
- Exempt-regex finding no longer suggests `^` on end-anchored branches (it produced `^\.(css|js)$`).
- Duplicate-rule findings use `(priority N)` rule references, which the validator reads; removed a double space in the title.
- Missing-baseline finding dropped a template sentence that described every Web ACL as "focused on DDoS and Bot protection".

### Changed
- The rule priority finding no longer compares rules against a generic order table. It reports only orderings with real consequences: labels consumed before they're produced, IP block lists after Allow rules, content inspection after Allow rules in default-Block Web ACLs, and Bot Control before blocking rules (cost only, Low).
- New "recommended protections" finding for default-Allow Web ACLs: missing Anti-DDoS AMR and IP reputation list (Medium), anonymous IP list and Bot Control (Low), each with where to place it. Default-Block allow-list Web ACLs don't get these recommendations.
- Missing-baseline finding is Low in default-Block Web ACLs and says CRS/KnownBadInputs must run before the Allow rules.
- Pre-checks read structured `leaves` (field, match type, value, text transformations, fallback, negation) recorded by the preprocessor, instead of parsing the summary string.

### New checks (12 pre-checks, 26 generators)
- UriFragment with `FallbackBehavior: MATCH` (always true; Critical in Allow rules)
- Allow rules with only forgeable, path-scoped conditions (Critical in default-Block Web ACLs, Medium otherwise)
- Path Block rules without `URL_DECODE` (encoding bypass)
- Literal `*` in byte matches, and query-string patterns on `UriPath` (never match)
- Managed rule groups in Count, and content rules overridden to Count (`SizeRestrictions_BODY` excluded on purpose)
- TGT_* overrides while Bot Control runs at COMMON level
- Checklist sections 19 (custom rule matching correctness), 20 (protections left in Count), and 21 (PCI DSS, LLM-reviewed for payment customers)

### Knowledge and workflow
- References: Bot Control version differences and COMMON-level blind spots, rate-based rule limits, body inspection limits, why 4xx auto-blocking doesn't help against burst scanning, Anti-DDoS AMR is not a scanning control, SQLi version lineages, PCI ASV scan interference and Requirement 6.4.2.
- AGENTS.md: English heading prefix and field labels are required so the scripts can parse translated reports; content rules for customer-facing findings; defined rule-reference format, the ⏳ marker, the self-review summary, and re-running Steps 4b to 6 after Step 7 changes; per-file output folders when a directory holds several Web ACLs.

## v0.5 (2026-09-29)

### Breaking
- No longer an installable skill. `SKILL.md`, `install.sh`, and `install.bat` are removed. The workflow now lives in `AGENTS.md`, and any agent that reads it can run a review. If you copied the skill into `~/.kiro/skills/` or similar, delete that copy.

### Workflow
- `AGENTS.md` is tool-neutral. It says "read", "write", and "run" instead of Kiro tool names (`fs_read`, `fs_write`), and resolves script paths relative to itself, so the old path probing in Step 0 is gone.
- `CLAUDE.md` imports `AGENTS.md` so Claude Code loads it.
- Works without cloning: point the agent at the raw `AGENTS.md` URL and it clones the repo into a temp directory.
- New Step 0 case: with no file given, the agent fetches the Web ACL through read-only AWS CLI calls (`list-web-acls`, `get-web-acl`, `get-logging-configuration`). It confirms the account first. Output goes to `./waf-review/<web-acl-name>/`.

### Scripts
- `waf-preprocess.py`: new `--logging <file>|none` option writes `web_acl.logging` into `waf-summary.json`.
- `waf-generate-findings.py`: the logging finding now follows the real status. Enabled means no finding, disabled gets a new "WAF logging is not enabled" finding, and unknown keeps the old "can't verify" finding. Before this, the finding appeared on every review.

## v0.4 (2026-04-21)

### Scripts (9 total, +2 new)
- `waf-generate-findings.py` **(NEW)**: 19 deterministic finding generators with bilingual templates (en/zh), three-way return logic (finding / NOT_APPLICABLE / AMBIGUOUS), section coverage computation. Produces ~80% of findings without LLM.
- `waf-build-issue-map.py` **(NEW)**: merges scripted rule mappings with LLM `**Rule**:` line parsing, validates against waf-summary.json. Replaces LLM-written issue-rule-mapping.json.
- `waf-pre-checks.py`: removed dead `_load_forgeability` code

### Finding generators (19 total)
Forgeable Allow (with opaque value detection), HostingProviderIPList Allow, scope-down too narrow, Challenge on POST/API, missing CRS/KnownBadInputs, token domain redundancy, no logging, default action redundancy, Count without labels, ChallengeAllDuringEvent disabled, unanchored exempt regex, missing crawler labeling, Bot Control CategorySearchEngine Allow, duplicate rules, managed versions, missing always-on Challenge, priority order, opaque search_string, managed Allow overrides.

### Knowledge files
- `antiddos-amr.md`: added tiered deployment patterns (front/back separation > dual AMR instance > single instance anti-pattern), baseline clarification, text/html labeling approach
- `crawler-seo.md`: reframed always-on Challenge as gap-window coverage for all reactive protections

### Workflow
- Step 3c: `waf-generate-findings.py` generates scripted findings with `--lang en|zh`
- Step 4: LLM only analyzes `llm_sections` (typically sections 5, 8, 17) — reads 3 reference files (~20KB) instead of 8 (~33KB)
- Step 4c: `waf-build-issue-map.py` replaces LLM-written issue-rule-mapping.json
- Step 7: adversarial re-derivation only on LLM-generated findings

### Performance
- LLM-written findings: ~21 → ~4 (for 27-rule example)
- Reference context read by LLM: ~33KB → ~20KB
- Measured total time: ~10 min for 27 rules, about the same as v0.3. LLM thinking is ~4 min of that

## v0.3 (2026-03-31)

### Scripts (7 total)
- `waf-preprocess.py`: structured rule extraction (56KB → 16KB), 3 JSON format support
- `waf-generate-mermaid.py`: auto Mermaid diagram with label dependency discovery, detailed/grouped modes
- `waf-pre-checks.py`: 6 mechanical checks (token domain, managed versions, default action redundancy, count without labels, challenge on POST/API, hosting provider allow) + forgeability/scope-down/regex flags
- `waf-generate-appendix.py`: generates fixed reference content (rule JSON templates, implementation steps, priority order, override recommendations) — LLM references appendix instead of reproducing
- `waf-generate-report-header.py`: auto Summary table + report header from Issue sections, idempotent re-runs
- `waf-annotate-mermaid.py`: issue annotation on Mermaid nodes with fold group expansion, auto-appends appendix
- `waf-validate-report.py`: report structure validation + pre-checks coverage enforcement

### Knowledge files (8 domain-specific files)
- Split single waf-knowledge.md into 8 files: antiddos-amr, bot-control, challenge-captcha, common-patterns, crawler-seo, ip-reputation, managed-overrides, rate-based
- Fixed content (JSON examples, operation steps) moved from knowledge files to script-generated appendix
- Checklist trimmed to 7KB (pure check instructions, no verbose explanations)

### Workflow
- Step 4 split into 9 sub-steps (4.1–4.9) for progressive knowledge loading
- LLM writes Issue sections only — header, Summary table, Mermaid diagram, and appendix all generated by scripts
- Pre-checks coverage validation: every FAIL pre-check must have corresponding finding in report
- Token domain: suffix-based matching covers all subdomain depths (not just single-level)

### Bug fixes
- Summary row counter skipped rows containing "Issue" in data cells
- Report header prepend not idempotent (duplicate headers on re-run)

## v0.2 (2026-03-24)

Checklist reorganized from 20 items to 18 items (two phases).

| Old # | New # | Change |
|-------|-------|--------|
| 1–5 | 1–5 | Unchanged |
| 6 | 17a | Merged into Phase 2 cross-rule analysis |
| 7 | 6 | Renumbered |
| 8 | 7 | Renumbered |
| 9 | 17b | Merged into Phase 2 fix impact analysis |
| 10 | — | Merged into section 3 (AntiDDoS AMR) |
| 11 | 8 | Renumbered |
| 12 | 18 | Moved to Phase 2 priority ordering |
| 13–19 | 9–15 | Renumbered |
| 20 | 16 | Renumbered |

## v0.1

Initial release.
