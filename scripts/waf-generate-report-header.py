#!/usr/bin/env python3
"""WAF Generate Report Header: Extract issues from report and prepend Summary table + header.

Usage: python3 waf-generate-report-header.py <output_dir>
  output_dir: directory containing waf-review-report.md and waf-summary.json

Reads waf-review-report.md (Issue sections only, no header/summary).
Prepends: report header (Web ACL name, date, objective) + Summary table.

The report file is modified in-place.
"""
import json
import os
import re
import sys
from datetime import date
from pathlib import Path
from waf_utils import fatal, work_path




SEVERITY_ORDER = {
    "critical": 0, "🔴 critical": 0, "🔴": 0,
    "medium": 1, "🟡 medium": 1, "🟡": 1,
    "low": 2, "🟢 low": 2, "🟢": 2,
    "awareness": 3, "🔵 awareness": 3, "🔵": 3,
}

SEVERITY_EMOJI = {
    "critical": "🔴 Critical", "🔴 critical": "🔴 Critical", "🔴": "🔴 Critical",
    "medium": "🟡 Medium", "🟡 medium": "🟡 Medium", "🟡": "🟡 Medium",
    "low": "🟢 Low", "🟢 low": "🟢 Low", "🟢": "🟢 Low",
    "awareness": "🔵 Awareness", "🔵 awareness": "🔵 Awareness", "🔵": "🔵 Awareness",
}


APPENDIX_START = "<!-- waf-appendix:start -->"
SEV_RANK = {"critical": 0, "medium": 1, "low": 2, "awareness": 3}
# Code blocks, inline code, and URLs keep their text when references are renumbered
_PROTECTED = re.compile(r"```.*?```|`[^`\n]*`|https?://\S+", re.DOTALL)


def _renumber(report: str) -> str:
    """Order Issue sections by severity, keeping their order within a severity,
    and renumber them 1..N. `Issue N` and `#N` references in the text follow
    the new numbers. Text after the appendix marker is regenerated later and
    left alone. Idempotent: a report already in order comes back unchanged."""
    cut = report.find(APPENDIX_START)
    body, tail = (report[:cut], report[cut:]) if cut != -1 else (report, "")
    heads = list(re.finditer(r"^## Issue (\d+) \(([^)]*)\)", body, re.MULTILINE))
    if not heads:
        return report
    pre = body[:heads[0].start()]
    secs = [body[h.start():(heads[i + 1].start() if i + 1 < len(heads) else len(body))]
            for i, h in enumerate(heads)]
    order = sorted(range(len(secs)), key=lambda i: (SEV_RANK.get(heads[i].group(2).strip().lower(), 9), i))
    old = [int(h.group(1)) for h in heads]
    new_of = {old[i]: pos + 1 for pos, i in enumerate(order)}
    if all(new_of[n] == n for n in old):
        return report

    def refs(text: str) -> str:
        def sub(part: str) -> str:
            part = re.sub(r"(Issue\s*#?)(\d+)", lambda m: m.group(1) + (
                f"\x00{new_of[int(m.group(2))]}\x00" if int(m.group(2)) in new_of else m.group(2)), part)
            return re.sub(r"(?<![\w&/#\x00])#(\d{1,3})(?!\d)", lambda m: "#" + (
                f"\x00{new_of[int(m.group(1))]}\x00" if int(m.group(1)) in new_of else m.group(1)), part)
        out, last = [], 0
        for m in _PROTECTED.finditer(text):
            out += [sub(text[last:m.start()]), m.group(0)]
            last = m.end()
        out.append(sub(text[last:]))
        return "".join(out).replace("\x00", "")

    ordered = []
    for pos, i in enumerate(order):
        first, rest = secs[i].split("\n", 1) if "\n" in secs[i] else (secs[i], "")
        first = re.sub(r"^## Issue \d+", f"## Issue {pos + 1}", first)
        ordered.append(first + ("\n" + refs(rest) if rest or "\n" in secs[i] else ""))
    return refs(pre) + "".join(ordered) + tail


def _extract_issues(report: str) -> list[dict]:
    """Extract issue number, severity, and title from ## Issue sections."""
    issues = []
    pattern = re.compile(
        r'^##\s+(?:Issue|问题)\s+#?(\d+)\s*\(([^)]+)\)\s*[:：]\s*(.+)',
        re.MULTILINE
    )
    for m in pattern.finditer(report):
        severity_raw = m.group(2).strip().lower()
        issues.append({
            "number": int(m.group(1)),
            "severity_raw": m.group(2).strip(),
            "severity_key": severity_raw,
            "title": m.group(3).strip(),
        })
    return issues


def _extract_impact(report: str, issue_number: int) -> str:
    """First line of the issue's **Problem** section, for the Summary table.
    Search only inside the issue's own section so a malformed Problem block
    can't pick up text from the next issue."""
    head = re.search(rf'^##\s+(?:Issue|问题)\s+#?{issue_number}\s*\(', report, re.MULTILINE)
    if not head:
        return ""
    nxt = re.search(r'^## ', report[head.end():], re.MULTILINE)
    section = report[head.end():head.end() + nxt.start()] if nxt else report[head.end():]
    m = re.search(r'\*\*(?:Problem|问题)\*\*\s*[:：]\s*(.*?)(?:\n\s*\n|\n\*\*|$)', section, re.DOTALL)
    if not m:
        return ""
    lines = [l.strip() for l in m.group(1).splitlines() if l.strip()]
    if not lines:
        return ""
    impact = re.sub(r'^[-•*]\s*', '', lines[0]).replace("|", "\\|")
    impact = re.sub(r'\s*[（(](?:Critical|Medium|Low|Awareness)[)）]$', '', impact)  # per-item severity tag
    if len(impact) > 80:
        impact = impact[:77]
        if impact.count("`") % 2:  # cut before a code span the limit would split
            impact = impact[:impact.rindex("`")].rstrip()
        impact = re.sub(r"[（(]?https?://\S*$", "", impact).rstrip()  # and before a URL
        impact += "..."
    return impact


def main():
    if len(sys.argv) < 2:
        fatal("Usage: waf-generate-report-header.py <output_dir>")

    output_dir = sys.argv[1]
    report_path = os.path.join(output_dir, "waf-review-report.md")
    summary_path = work_path(output_dir, "waf-summary.json")

    if not os.path.isfile(report_path):
        fatal(f"waf-review-report.md not found in {output_dir}")
    if not os.path.isfile(summary_path):
        fatal(f"waf-summary.json not found in {output_dir}")

    report = Path(report_path).read_text(encoding="utf-8")
    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    first_issue = re.search(r'^## Issue \d+', report, re.MULTILINE)
    if first_issue:  # drop an earlier header before renumbering
        report = report[first_issue.start():]
    report = _renumber(report)

    web_acl = summary.get("web_acl", {})
    acl_name = web_acl.get("name", "unknown")
    today = date.today().isoformat()

    issues = _extract_issues(report)
    if not issues:
        fatal("No Issue sections found in report")

    # Sort by severity for Summary table display (issues keep original order in report)
    sorted_issues = sorted(issues, key=lambda i: SEVERITY_ORDER.get(i["severity_key"], 9))

    # Build Summary table
    meta_path = work_path(output_dir, "findings-metadata.json")
    zh = os.path.isfile(meta_path) and json.loads(
        Path(meta_path).read_text(encoding="utf-8")).get("lang") == "zh"
    table_lines = [
        "| 严重程度 | 问题 | 影响 |" if zh else "| Severity | Issue | Impact |",
        "|----------|-------|--------|",
    ]
    for issue in sorted_issues:
        severity_display = SEVERITY_EMOJI.get(issue["severity_key"], issue["severity_raw"])
        impact = _extract_impact(report, issue["number"])
        table_lines.append(f"| {severity_display} | #{issue['number']} {issue['title']} | {impact} |")

    summary_table = "\n".join(table_lines)

    # Build header
    if zh:
        head = (f"# AWS WAF Web ACL 规则评审报告\n\n**Web ACL**：{acl_name}\n**评审日期**：{today}\n"
                "**目的**：检查 WAF 配置中的安全问题、配置错误和可优化之处\n\n## 摘要")
    else:
        head = (f"# AWS WAF Web ACL Rules Review Report\n\n**Web ACL**: {acl_name}\n**Review Date**: {today}\n"
                "**Objective**: Review WAF configuration for security issues, misconfigurations, "
                "and optimization opportunities\n\n## Summary")
    header = f"""{head}

{summary_table}

---

"""

    # Strip existing header if present (idempotent re-runs)
    first_issue = re.search(r'^## Issue \d+', report, re.MULTILINE)
    if first_issue:
        report = report[first_issue.start():]

    # Prepend header to report
    new_report = header + report
    Path(report_path).write_text(new_report, encoding="utf-8")

    print(f"Generated header with {len(issues)} issues in Summary table", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"ISSUE_COUNT: {len(issues)}")


if __name__ == "__main__":
    main()
