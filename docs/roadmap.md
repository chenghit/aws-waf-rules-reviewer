# Roadmap

## v0.3 (current)

Script-assisted workflow: 5 preprocessing scripts + 1 report header script handle structured extraction, Mermaid generation, mechanical pre-checks, and report validation. LLM focuses on security analysis and report writing.

Known limitation: ~10 min thinking time for 27 rules. Root cause identified — 60KB reference context (checklist.md + waf-knowledge.md) dominates thinking time. This is the cost of high-quality domain-specific analysis and is expected to improve with future model iterations.

## v0.4 (planned)

### Rule grouping in pre-checks

For 100+ rule Web ACLs, many rules share the same issue pattern:
- 20 rate-based rules all using Challenge on API paths → one finding covers all
- Multiple Count+Label rules with identical labeling patterns → group analysis
- Duplicate/mirrored rules (same logic, different names) → flag as redundant

`waf-pre-checks.py` detects similar rules and outputs grouped flags:
```json
{
  "flags": {
    "similar_rule_groups": [
      {
        "pattern": "rate_based_challenge_on_api",
        "rules": ["rule1", "rule2", ...],
        "shared_issue": "Challenge action on API paths effectively equals Block"
      }
    ]
  }
}
```

LLM writes one finding per group instead of per rule. Reduces both thinking time and report size for large Web ACLs.

### Pre-checks generate full finding Markdown

For FAIL items and high-confidence flags (e.g., `all_forgeable: true, blast_radius: global`), `waf-pre-checks.py` outputs complete Issue section Markdown — not just status + one-line finding. LLM copies these directly into the report without re-deriving.

Estimated impact: ~5-8 issues handled by script, LLM only generates ~8-10 issues from scratch.

## Future considerations

### Context size optimization

Experiments showed thinking time is dominated by reference context size (60KB), not rule count or section count. Potential approaches:
- Inline critical knowledge into checklist sections (risk: duplication increases total size)
- Trim references based on detected rule types (limited ROI — most sections are universally relevant)
- Wait for model improvements in long-context reasoning efficiency

### Thinking budget control

If agent frameworks expose thinking budget parameters (e.g., `thinking.budget_tokens`), experiment with capping thinking to find the quality/speed sweet spot.
