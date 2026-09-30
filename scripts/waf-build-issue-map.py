#!/usr/bin/env python3
"""WAF Build Issue Map: Map rules to the issues that cite them in waf-review-report.md.

Usage: python3 waf-build-issue-map.py <output_dir>
  output_dir: directory containing waf-review-report.md and work/waf-summary.json

The report is the source of truth: scripted findings may have been removed or
renumbered in Step 4, so every issue's **Rule**:/**Rules**: line is read.

Outputs: {output_dir}/issue-rule-mapping.json
"""
import json
import os
import re
import sys
from pathlib import Path
from waf_utils import fatal, work_path




def _extract_rule_refs(report: str, valid_rules: set) -> dict:
    """Parse the **Rule**:/**Rules**: lines of every Issue section."""
    mapping = {}
    current_issue = None
    for line in report.split("\n"):
        m = re.match(r'^## Issue (\d+)\s', line)
        if m:
            current_issue = int(m.group(1))
            continue
        if current_issue is None:
            continue
        if not line.startswith("**Rule"):
            continue
        # Extract rule names from **Rule**: or **Rules**: lines
        # Patterns: "name (priority N)", "name (PN)"
        for rm in re.finditer(r'([\w.\-:]+)\s*\((?:priority\s*|P)(\d+)\)', line):
            rule_name = rm.group(1)
            if rule_name not in valid_rules:
                continue
            if rule_name in mapping:
                mapping[rule_name] += f", #{current_issue}"
            else:
                mapping[rule_name] = f"⚠️ Issue #{current_issue}"
    return mapping


def main():
    if len(sys.argv) < 2:
        fatal("Usage: waf-build-issue-map.py <output_dir>")

    output_dir = sys.argv[1]
    report_path = os.path.join(output_dir, "waf-review-report.md")
    summary_path = work_path(output_dir, "waf-summary.json")

    for p in (report_path, summary_path):
        if not os.path.isfile(p):
            fatal(f"{os.path.basename(p)} not found in {output_dir}")

    report = Path(report_path).read_text(encoding="utf-8")
    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))

    # Build set of valid rule names
    valid_rules = {r["name"] for r in summary.get("rules", [])}

    mapping = _extract_rule_refs(report, valid_rules)

    # Write output
    output = {"annotations": mapping}
    output_file = work_path(output_dir, "issue-rule-mapping.json")
    Path(output_file).write_text(
        json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Mapped {len(mapping)} rules to issues", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"OUTPUT_FILE: {output_file}")
    print(f"RULES_MAPPED: {len(mapping)}")


if __name__ == "__main__":
    main()
