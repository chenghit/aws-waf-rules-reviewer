#!/usr/bin/env python3
"""WAF Pre-checks: Run mechanical checks and extract flags from waf-summary.json.

Usage: python3 waf-pre-checks.py <output_dir> <input_file>
  output_dir: directory containing waf-summary.json
  input_file: original WAF JSON file (for detailed field inspection)

Outputs: {output_dir}/pre-checks.json
"""
import json
import os
import re
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent

# ── Forgeability mapping ──────────────────────────────────────────────────

def _load_forgeability() -> dict:
    p = SCRIPTS_DIR / "managed-labels.json"
    if not p.exists():
        return {"forgeable_field_types": [], "unforgeable_statement_types": [],
                "unforgeable_field_types": []}
    data = json.loads(p.read_text(encoding="utf-8"))
    return data.get("forgeability", {})

FORGEABLE_FIELDS = {
    "single_header", "single_query_argument", "cookie", "cookies",
    "body", "json_body", "uri_path", "query_string", "method",
    "header_order", "headers",
}
UNFORGEABLE_STMT_TYPES = {
    "ip_set", "asn_match", "geo_match", "rate_based",
}
UNFORGEABLE_FIELDS = {
    "ja3_fingerprint", "ja4_fingerprint",
}

ALL_KNOWN_FIELDS = FORGEABLE_FIELDS | UNFORGEABLE_FIELDS | UNFORGEABLE_STMT_TYPES | {"label_match"}

def _classify_condition(summary: str) -> tuple[list, list]:
    """Parse statement summary and classify conditions as forgeable/unforgeable."""
    forgeable = []
    unforgeable = []

    # Extract known field types from summary (ignore quoted values)
    # Match patterns like: "single_header:user-agent EXACTLY", "ip_set '...'", "asn_match [..."
    for match in re.finditer(r'([\w]+(?::[\w:.-]+)?)\s+(?:EXACTLY|STARTS_WITH|ENDS_WITH|CONTAINS|\'|\[)', summary):
        field = match.group(1)
        base_field = field.split(":")[0]

        if base_field not in ALL_KNOWN_FIELDS:
            continue  # skip non-field tokens (e.g., search_string values)

        if base_field in UNFORGEABLE_FIELDS or base_field in UNFORGEABLE_STMT_TYPES:
            unforgeable.append(field)
        elif base_field == "label_match":
            unforgeable.append(field)
        else:
            forgeable.append(field)

    # Check for statement-level patterns not caught by field regex
    for stmt_type in UNFORGEABLE_STMT_TYPES:
        if stmt_type in summary and stmt_type not in [u.split(":")[0] for u in unforgeable]:
            unforgeable.append(stmt_type)

    return forgeable, unforgeable

def _has_uri_constraint(summary: str) -> bool:
    """Check if statement contains a meaningful URI path constraint.
    uri_path STARTS_WITH '/' matches all traffic — not a real constraint."""
    if not re.search(r'uri_path\s+(?:EXACTLY|STARTS_WITH|ENDS_WITH|CONTAINS)', summary):
        return False
    # STARTS_WITH '/' matches everything — treat as no constraint
    if re.search(r"uri_path\s+STARTS_WITH\s+'/'", summary):
        return False
    return True

# ── Pre-checks ────────────────────────────────────────────────────────────

def _check_token_domain(web_acl: dict) -> dict:
    """Check #11: token_domains redundancy."""
    domains = web_acl.get("token_domains", [])
    if not domains:
        return {"status": "PASS", "finding": None}

    # Find apex domains and their subdomains
    issues = []
    apex_domains = set()
    for d in domains:
        parts = d.split(".")
        if len(parts) == 2:  # apex domain like example.com
            apex_domains.add(d)

    redundant = []
    for d in domains:
        parts = d.split(".")
        if len(parts) == 2:
            continue  # apex itself
        # Check if parent apex covers this subdomain
        apex = ".".join(parts[-2:])
        if apex in apex_domains and len(parts) == 3:
            redundant.append(d)

    # Check for missing apex
    all_apexes = set()
    for d in domains:
        parts = d.split(".")
        all_apexes.add(".".join(parts[-2:]))
    missing_apex = all_apexes - apex_domains

    if redundant:
        issues.append(f"Redundant subdomains (covered by apex): {', '.join(redundant)}")
    if missing_apex:
        issues.append(f"Missing apex domains (add to cover subdomains): {', '.join(missing_apex)}")

    if issues:
        return {"status": "FAIL", "finding": "; ".join(issues),
                "domains": domains, "redundant": redundant,
                "missing_apex": list(missing_apex)}
    return {"status": "PASS", "finding": None}

def _check_managed_versions(rules: list) -> dict:
    """Check #12: managed rule group versions."""
    issues = []
    for r in rules:
        mg = r.get("managed")
        if not mg:
            continue
        gn = mg.get("group_name", "")
        ver = mg.get("version", "")

        if "SQLiRuleSet" in gn or "sqli" in gn.lower():
            # Check if version < 2.0
            m = re.search(r'(\d+)\.(\d+)', ver)
            if m and int(m.group(1)) < 2:
                issues.append(f"{r['name']}: SQLiRuleSet version {ver} < 2.0 (recommend upgrading)")

        if "BotControlRuleSet" in gn or "bot_control" in gn.lower():
            m = re.search(r'(\d+)\.(\d+)', ver)
            if m and int(m.group(1)) < 5:
                issues.append(f"{r['name']}: BotControlRuleSet version {ver} < 5.0 (recommend upgrading)")

    if issues:
        return {"status": "FAIL", "finding": "; ".join(issues), "details": issues}
    return {"status": "PASS", "finding": None}

def _check_default_action_redundancy(web_acl: dict, rules: list) -> dict:
    """Check #15: redundant trailing Allow-all rule."""
    if web_acl.get("default_action") != "allow":
        return {"status": "PASS", "finding": None}
    if not rules:
        return {"status": "PASS", "finding": None}

    last = rules[-1]
    if last["action"] == "allow":
        summary = last.get("statement", {}).get("summary", "")
        # Check if it matches all traffic (URI STARTS_WITH '/' or similar)
        if ("STARTS_WITH '/'" in summary or summary == "EMPTY"
                or "uri_path STARTS_WITH '/'" in summary):
            return {"status": "FAIL",
                    "finding": f"Rule '{last['name']}' (priority {last['priority']}) matches all traffic with Allow, "
                               f"but default_action is already Allow. This rule is redundant.",
                    "rule": last["name"], "priority": last["priority"]}
    return {"status": "PASS", "finding": None}

def _check_count_without_labels(rules: list) -> dict:
    """Check #17a: custom Count rules without RuleLabels."""
    flagged = []
    for r in rules:
        if (r["action"] == "count" and r["type"] == "custom"
                and not r.get("rule_labels")):
            flagged.append({"name": r["name"], "priority": r["priority"]})

    if flagged:
        names = ", ".join(f["name"] for f in flagged)
        return {"status": "FAIL",
                "finding": f"Custom Count rules without labels (metric-only): {names}",
                "rules": flagged}
    return {"status": "PASS", "finding": None}

def _check_wcu_reminder(web_acl: dict) -> dict:
    """Check #10: WCU capacity reminder."""
    capacity = web_acl.get("capacity")
    if capacity is not None:
        return {"status": "INFO",
                "finding": f"Current WCU: {capacity}/5000. Verify capacity before adding new rules."}
    return {"status": "INFO",
            "finding": "WCU capacity unknown (not in JSON). Verify in AWS Console before adding rules."}

# ── Flags ─────────────────────────────────────────────────────────────────

def _flag_allow_rules(rules: list) -> list:
    """Flag all Allow rules with forgeability analysis."""
    flags = []
    for r in rules:
        if r["action"] != "allow":
            continue
        summary = r.get("statement", {}).get("summary", "")
        forgeable, unforgeable = _classify_condition(summary)
        all_forgeable = len(unforgeable) == 0 and len(forgeable) > 0
        blast_radius = "path_scoped" if _has_uri_constraint(summary) else "global"

        flags.append({
            "name": r["name"],
            "priority": r["priority"],
            "statement_summary": summary,
            "forgeable_conditions": forgeable,
            "unforgeable_conditions": unforgeable,
            "all_forgeable": all_forgeable,
            "blast_radius": blast_radius,
        })
    return flags

def _flag_scope_downs(rules: list) -> list:
    """Flag all scope-down statements for LLM review."""
    flags = []
    for r in rules:
        sd = r.get("scope_down")
        if not sd:
            continue
        flags.append({
            "rule": r["name"],
            "priority": r["priority"],
            "rule_type": r["type"],
            "scope_down_summary": sd["summary"],
            "source_lines": sd.get("source_lines"),
        })
    return flags

def _split_regex_branches(regex: str) -> list[str]:
    """Split regex on | only at top level (outside parentheses)."""
    branches = []
    depth = 0
    current = []
    escaped = False
    for ch in regex:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == '\\':
            current.append(ch)
            escaped = True
            continue
        if ch == '(':
            depth += 1
            current.append(ch)
        elif ch == ')':
            depth -= 1
            current.append(ch)
        elif ch == '|' and depth == 0:
            branches.append(''.join(current))
            current = []
        else:
            current.append(ch)
    if current:
        branches.append(''.join(current))
    return branches

def _flag_exempt_regex(rules: list) -> list:
    """Flag AntiDDoS AMR exempt URI regex branches with anchoring analysis."""
    flags = []
    for r in rules:
        mg = r.get("managed")
        if not mg:
            continue
        cfg = mg.get("config") or {}
        exempt = cfg.get("uris_exempt_from_challenge", [])
        if not exempt:
            continue

        regex_str = exempt[0] if isinstance(exempt, list) and exempt else str(exempt)
        branches = _split_regex_branches(regex_str)
        branch_analysis = []
        for b in branches:
            b = b.strip()
            branch_analysis.append({
                "pattern": b,
                "anchored_start": b.startswith("^"),
                "anchored_end": b.endswith("$"),
            })
        flags.append({
            "rule": r["name"],
            "priority": r["priority"],
            "full_regex": regex_str,
            "branches": branch_analysis,
        })
    return flags

# ── Main ──────────────────────────────────────────────────────────────────

def _fatal(msg: str):
    print(msg, file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: FATAL")
    print(f"ACTION: FIX")
    print(f"CONTEXT: {msg}")
    sys.exit(2)

def main():
    if len(sys.argv) < 3:
        _fatal("Usage: waf-pre-checks.py <output_dir> <input_file>")

    output_dir = sys.argv[1]
    input_file = sys.argv[2]
    summary_file = os.path.join(output_dir, "waf-summary.json")

    if not os.path.isfile(summary_file):
        _fatal(f"waf-summary.json not found in {output_dir}")

    try:
        summary = json.loads(Path(summary_file).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        _fatal(f"Failed to read {summary_file}: {e}")

    web_acl = summary.get("web_acl", {})
    rules = summary.get("rules", [])

    # Run pre-checks
    pre_checks = {
        "token_domain": _check_token_domain(web_acl),
        "managed_versions": _check_managed_versions(rules),
        "default_action_redundancy": _check_default_action_redundancy(web_acl, rules),
        "count_without_labels": _check_count_without_labels(rules),
        "wcu_reminder": _check_wcu_reminder(web_acl),
    }

    # Build flags
    flags = {
        "allow_rules": _flag_allow_rules(rules),
        "scope_downs": _flag_scope_downs(rules),
        "exempt_regex_branches": _flag_exempt_regex(rules),
    }

    result = {"pre_checks": pre_checks, "flags": flags}

    # Write output
    output_file = os.path.join(output_dir, "pre-checks.json")
    try:
        Path(output_file).write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        _fatal(f"Failed to write {output_file}: {e}")

    checks_run = len(pre_checks)
    checks_failed = sum(1 for v in pre_checks.values() if v["status"] == "FAIL")

    print(f"Ran {checks_run} checks, {checks_failed} failed", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"CHECKS_RUN: {checks_run}")
    print(f"CHECKS_FAILED: {checks_failed}")

if __name__ == "__main__":
    main()
