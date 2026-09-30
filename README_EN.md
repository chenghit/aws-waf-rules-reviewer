# AWS WAF Rules Reviewer

<!-- NOTE: Keep README.md and README_EN.md in sync when making changes. -->

[中文版](README.md)

A tool for AI coding agents that reviews AWS WAF Web ACL configurations for security issues, misconfigurations, and optimization opportunities. There's nothing to install. Your agent reads [AGENTS.md](AGENTS.md) and follows it. It works with Claude Code, Codex, Cursor, Kiro, and any other agent that can run shell commands.

> [!WARNING]
> Don't use Claude Opus 5.5 or Claude Sonnet 5.5. Use an earlier Claude model, such as Claude Sonnet 5.
>
> A review makes the agent analyze security material: SQLi/XSS rule matches, bypass paths, and bot and DDoS protections. While reviewing real Web ACLs with Claude Opus 5.5, a safety classifier stopped the report from being written, with `Error: Not run: the response that made this tool call was stopped by a safety classifier.` Claude Sonnet 5.5 came out after Opus 5.5 and is likely to have the same problem.
>
> Don't use GPT-family models on Amazon Bedrock either, unless you have tested your exact workflow. Upstream cyber-safety checks can silently block this kind of defensive WAF analysis, and the agent then looks like it stopped responding.

## Workflow

```mermaid
flowchart LR
    A["Web ACL JSON / AWS CLI"] --> B["Preprocess"]
    B --> C["Mermaid Gen"]
    B --> D["Pre-checks"]
    D --> D2["Appendix Gen"]
    D2 --> D3["Findings Gen"]
    C --> E["LLM Analysis"]
    D3 --> E
    E --> E2["Report Header"]
    E2 --> E3["Issue Map"]
    E3 --> F["Mermaid Annotate"]
    F --> G["Report Validate"]
    G --> H["LLM Self-review"]
    H --> J["HTML Render"]
    J --> I["Review Report"]

    style B fill:#e1f5fe
    style C fill:#e1f5fe
    style D fill:#e1f5fe
    style D2 fill:#e1f5fe
    style D3 fill:#e1f5fe
    style E2 fill:#e1f5fe
    style E3 fill:#e1f5fe
    style F fill:#e1f5fe
    style G fill:#e1f5fe
    style J fill:#e1f5fe
    style E fill:#fff3e0
    style H fill:#fff3e0
```

Blue = Python scripts (deterministic), Orange = LLM reasoning

Scripts handle structured extraction, diagram generation, mechanical validation, and deterministic finding generation. LLM focuses only on judgment-heavy security analysis (Bot Control strategy, cookie logic, cross-rule dependencies).

## What It Does

Given a Web ACL, either as a JSON file or fetched from your account, the agent:

1. **Fetches** (optional): pulls the Web ACL and its logging config with read-only AWS CLI calls
2. **Preprocesses**: extracts structured rule summaries, compresses input (56KB → 16KB)
3. **Pre-checks**: automatically detects token domain redundancy, outdated versions, redundant rules, challenge on POST/API paths, and other deterministic issues (19 checks total)
4. **Deterministic findings**: 30 generators auto-produce most findings (forgeable Allow, forgeable exemptions, path-only Allow, UriFragment conditions that always match, path rules without URL decoding, protections left in Count, unpinned managed rule versions, ordering problems with real consequences, recommended protections, etc.) with bilingual support (en/zh)
5. **LLM analysis**: only analyzes judgment-heavy checklist items (Bot Control strategy, cookie logic, cross-rule dependencies) from the sections not covered by scripts
6. **Report generation**: severity-rated findings (Critical / Medium / Low / Awareness)
7. **Mermaid flow diagram**: auto-generated rule execution flow with issue annotations
8. **Self-review**: mechanical validation + adversarial checks (LLM-generated findings only) for report accuracy
9. **HTML report**: a script turns the Markdown report into a single HTML file that needs no JavaScript, works offline, and links issue numbers to their findings

## Usage

There's no install step. You need Python 3.10+ (standard library only), and your agent needs to be able to run shell commands.

**From any project.** Tell your agent:

> Read https://raw.githubusercontent.com/chenghit/aws-waf-rules-reviewer/main/AGENTS.md and review my AWS WAF Web ACL.

The agent clones this repo into a temp directory and runs the scripts from there. The report goes under your current directory.

**From a clone.**

```bash
git clone https://github.com/chenghit/aws-waf-rules-reviewer.git
cd aws-waf-rules-reviewer
```

Start your agent in that directory. Codex, Cursor, and most other agents load `AGENTS.md` on their own. Claude Code loads it through `CLAUDE.md`. If yours doesn't, begin with "read AGENTS.md". Then ask for a review, e.g. "review the Web ACL prod-acl in us-east-1" or "review examples/web-acl-example.json".

## Input

**A JSON file or directory.** Export it from the AWS Console (Web ACL → "Download web ACL as JSON") or with `aws wafv2 get-web-acl`. You can give the file path, or a directory that contains the file. Three JSON formats work: AWS CLI output (PascalCase), Console export, and snake_case custom formats.

**Nothing.** The agent fetches the Web ACL with the AWS CLI. It first shows you the account from `aws sts get-caller-identity`, then asks for the scope, the region, and which Web ACL. It only makes read calls, so your credentials need `wafv2:ListWebACLs`, `wafv2:GetWebACL`, and `wafv2:GetLoggingConfiguration`. It also fetches the logging config, which a JSON export doesn't include, so the report can say whether logging is actually on.

## Output

The report comes as two files: `waf-review-report.html` to read and share, and `waf-review-report.md` to edit (ask the agent to render the HTML again after editing). For a local file they go in `waf-review/` next to that file. For a fetched Web ACL they go in `./waf-review/<web-acl-name>/`. Intermediate files, including the fetched `web-acl.json` and `logging-configuration.json`, sit in a `work/` subfolder you can ignore. The report contains:

- **Summary table**: all findings with severity and impact at a glance
- **Detailed findings**: each issue with the affected rule, current state, problem description, and recommendation
- **Items needing user confirmation**: findings where business context may change the severity, marked with ⏳
- **Appendix: Rule Execution Flow**: the rules in priority order, with each rule's action and related issues. A Mermaid diagram in the Markdown, drawn as cards in the HTML

### Severity Levels

| Level | Meaning |
|-------|---------|
| 🔴 Critical | Attackers can bypass protection entirely, or a core mechanism is disabled |
| 🟡 Medium | Protection gap exists but requires specific conditions to exploit |
| 🟢 Low | Suboptimal configuration without direct security impact |
| 🔵 Awareness | Not a vulnerability. Operational information the user should know |

## Performance Expectations

v0.4 moves ~80% of findings from LLM analysis to deterministic script generation, significantly reducing LLM output volume and reference context reads.

| Rule Count | LLM Analysis (Step 4) | Self-review (Step 7) | All Script Steps | Total |
|-----------|----------------------|---------------------|-----------------|-------|
| 27 rules (measured, v0.7.1) | ~7.7 min | ~1.4 min | < 10 s | ~9.6 min |

Measured with Claude Code and Claude Opus 5.5 on `examples/web-acl-example.json`.

> Compared to v0.3, total time has not decreased significantly, but user experience is noticeably better: only Step 4 (LLM analysis) has a thinking wait period. All other steps produce continuous output. Additionally, scripted findings support bilingual output (en/zh) and provide richer report details.

## Examples

The `examples/` directory contains a complete input/output example:

- `web-acl-example.json`: assembled 27-rule WAF configuration (covers AntiDDoS AMR, Bot Control, rate-based, custom rules, and other typical scenarios)
- `waf-review/waf-review-report.html` and `waf-review/waf-review-report.md`: actual review report output (Chinese)
- `waf-review/work/`: script-generated intermediate files (summary, pre-checks, Mermaid diagrams, etc.)

Generated with Claude Code and Claude Opus 5.5. The example configuration is synthetic and didn't trigger the safety classifier this time, but real configurations have; see the warning at the top.

## Checklist Coverage

The review covers 21 categories:

**Phase 1: Independent Checks**

1. Allow rules audit (forgeability, bypass risk)
2. Scope-down statements (too narrow / too broad, forgeable exemptions)
3. AntiDDoS AMR configuration (ChallengeAllDuringEvent, exempt regex, SEO impact, dual instance pattern)
4. Challenge action applicability (POST/API/native app limitations, Count-to-Challenge staging risk)
5. Bot Control configuration (Allow override risks, verified vs unverified bots)
6. Rate-based rules (activation delay, threshold reasonableness, overlapping scope-down)
7. IP reputation and anonymous IP rules
8. Landing page and cookie-based logic
9. Missing baseline protections (CRS, KnownBadInputs)
10. WCU capacity awareness
11. Token domain configuration
12. Managed rule group versions (unpinned groups, old Bot Control versions, SQLi version lineages)
13. Logging and monitoring
14. (Merged into item 1) Fixed values in rules are judged by forgeability, not treated as leaked because they sit in the config
15. Default action (redundant trailing Allow-all detection)
16. Always-on Challenge for landing pages (proactive DDoS defense, immunity time, crawler exclusion)

**Phase 2: Global Cross-checks**

17. Cross-rule and label dependency analysis (label source verification + fix impact analysis)
18. Rule priority ordering (only orderings with real consequences: labels consumed before they're produced, labels no rule adds, rules an earlier Allow or Block always ends first, block lists after Allow rules, inspection after Allow rules in allow-list ACLs)

**Additional Checks**

19. Custom rule matching correctness (URL decoding on path rules, literal wildcards, query patterns on UriPath, UriFragment fallback, patterns a case transform makes unmatchable)
20. Protections left in Count (whole managed groups, content rules overridden to Count)
21. PCI DSS considerations for payment customers (ASV scan interference, Requirement 6.4.2)

## Version History

See [CHANGELOG.md](CHANGELOG.md).

## Model Requirements

The model needs at least 64K output tokens: reports can be long, and the self-review stage needs extra output room. A model with a 1M context window is recommended, since large Web ACLs and the reference files all go into the context. Read the warning at the top before choosing a model.
## Disclaimer

This tool is powered by AI, which may produce inaccurate or incomplete findings. The generated report is a starting point for human review and doesn't replace it. Always verify findings against the actual WAF configuration and your business context before making changes.
