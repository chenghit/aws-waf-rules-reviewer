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
from waf_utils import fatal

# ── Forgeability mapping ──────────────────────────────────────────────────
# Keep in sync with managed-labels.json (forgeability section).

UNFORGEABLE_LEAF_TYPES = {"ip_set", "asn_match", "geo_match", "label_match"}
UNFORGEABLE_FIELDS = {"ja3_fingerprint", "ja4_fingerprint"}

# Managed groups that inspect request content (signatures), as opposed to
# IP reputation, bot, fraud, and DDoS groups.
CONTENT_GROUPS = {
    "AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesSQLiRuleSet", "AWSManagedRulesLinuxRuleSet",
    "AWSManagedRulesUnixRuleSet", "AWSManagedRulesWindowsRuleSet",
    "AWSManagedRulesPHPRuleSet", "AWSManagedRulesWordPressRuleSet",
    "AWSManagedRulesAdminProtectionRuleSet",
}
# Rule overrides to Count that are common, deliberate practice
ACCEPTED_COUNT_OVERRIDES = {"SizeRestrictions_BODY"}
# AWS does not version the IP reputation groups
UNVERSIONED_GROUPS = {"AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesAnonymousIpList"}
DECODE_TRANSFORMS = {"URL_DECODE", "URL_DECODE_UNI"}
CASE_TRANSFORMS = {"LOWERCASE", "UPPERCASE"}

LABELS = json.loads((Path(__file__).parent / "managed-labels.json").read_text(encoding="utf-8"))


def _leaves(rule: dict, include_scope_down: bool = False) -> list:
    leaves = list(rule.get("statement", {}).get("leaves", []))
    if include_scope_down and rule.get("scope_down"):
        leaves += rule["scope_down"].get("leaves", [])
    return leaves


def _classify_leaves(leaves: list) -> tuple[list, list]:
    """Split a rule's match conditions into forgeable and unforgeable ones."""
    forgeable, unforgeable = [], []
    for l in leaves:
        if l["type"] in UNFORGEABLE_LEAF_TYPES:
            name = l["type"]
        elif l["field"] in UNFORGEABLE_FIELDS:
            name = l["field"]
        else:
            if l["field"] not in forgeable:
                forgeable.append(l["field"])
            continue
        if name not in unforgeable:
            unforgeable.append(name)
    return forgeable, unforgeable


def _has_uri_constraint(leaves: list) -> bool:
    """True if a non-negated URI path condition limits the rule to some paths.
    uri_path STARTS_WITH '/' matches all traffic, so it doesn't count."""
    return any(l["field"] == "uri_path" and not l["negated"]
               and not (l["match"] == "STARTS_WITH" and l["value"] == "/")
               for l in leaves)


def _ref(r: dict) -> dict:
    return {"name": r["name"], "priority": r["priority"]}

# ── Pre-checks ────────────────────────────────────────────────────────────

def _check_token_domain(web_acl: dict) -> dict:
    """Check #11: token_domains redundancy."""
    domains = web_acl.get("token_domains", [])
    if not domains:
        return {"status": "PASS", "finding": None}

    # Find apex domains and their subdomains.
    # Heuristic: the shortest domain for each TLD suffix is the apex.
    # This handles multi-part TLDs like .co.uk, .com.cn, .co.jp.
    issues = []

    # Group domains by their last-2 parts (potential simple TLD)
    # Then identify apex as the shortest domain in each suffix group
    apex_domains = set()
    # Sort by part count ascending — shortest first
    sorted_domains = sorted(domains, key=lambda d: len(d.split(".")))
    for d in sorted_domains:
        # A domain is an apex if no existing apex is a suffix of it
        is_sub = any(d.endswith("." + apex) for apex in apex_domains)
        if not is_sub:
            apex_domains.add(d)

    redundant = []
    for d in domains:
        if d in apex_domains:
            continue  # apex itself
        # Check if any apex covers this subdomain (suffix match)
        covering_apex = next((a for a in apex_domains if d.endswith("." + a)), None)
        if covering_apex:
            redundant.append(d)

    # Check for missing apex: domains whose apex (shortest covering suffix)
    # is not in the token_domains list
    missing_apex = set()
    for d in domains:
        if d in apex_domains:
            continue
        has_covering = any(d.endswith("." + a) for a in apex_domains)
        if not has_covering:
            # This domain has no covering apex in the list — it IS an apex
            # (already handled above), or its apex is missing.
            # Since we already identified all apexes, this shouldn't happen,
            # but guard against it.
            missing_apex.add(d)

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
    """Check #12: managed rule groups not pinned to a static version, or pinned
    to an old Bot Control version."""
    unpinned, outdated = [], []
    for r in rules:
        mg = r.get("managed")
        if not mg or mg.get("vendor", "AWS") != "AWS":
            continue
        gn = mg.get("group_name", "")
        if gn in UNVERSIONED_GROUPS:
            continue
        ver = mg.get("version", "")
        if not ver:
            unpinned.append(dict(_ref(r), group=gn))
            continue
        m = re.search(r'(\d+)\.(\d+)', ver)
        if m and "BotControl" in gn and int(m.group(1)) < 5:
            outdated.append(dict(_ref(r), group=gn, version=ver))
    if unpinned or outdated:
        parts = [f"{u['name']}: {u['group']} not pinned (follows AWS default version)" for u in unpinned]
        parts += [f"{o['name']}: {o['group']} pinned to {o['version']}" for o in outdated]
        return {"status": "FAIL", "finding": "; ".join(parts),
                "unpinned": unpinned, "outdated": outdated,
                "rules": unpinned + outdated}
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
        if (r["action"] == "count" and r["type"] in ("custom", "rate_based")
                and not r.get("rule_labels")):
            flagged.append({"name": r["name"], "priority": r["priority"]})

    if flagged:
        names = ", ".join(f["name"] for f in flagged)
        return {"status": "FAIL",
                "finding": f"Count rules without labels (metric-only): {names}",
                "rules": flagged}
    return {"status": "PASS", "finding": None}


def _check_challenge_on_post_api(rules: list) -> dict:
    """Check #4: Challenge/CAPTCHA on POST or API paths (effectively Block)."""
    flagged = []
    for r in rules:
        if r["action"] not in ("challenge", "captcha"):
            continue
        summary = r.get("statement", {}).get("summary", "")
        reasons = []
        if "method EXACTLY 'POST'" in summary or "method EXACTLY 'PUT'" in summary:
            reasons.append("targets POST/PUT requests")
        if "/api/" in summary or "/api'" in summary:
            reasons.append("targets API path")
        if reasons:
            flagged.append({"name": r["name"], "priority": r["priority"],
                            "reasons": reasons})
    if flagged:
        details = "; ".join(f"{f['name']} (P{f['priority']}): {', '.join(f['reasons'])}" for f in flagged)
        return {"status": "FAIL",
                "finding": f"Challenge/CAPTCHA on non-browser paths (effectively Block): {details}",
                "rules": flagged}
    return {"status": "PASS", "finding": None}

def _check_hosting_provider_allow(rules: list) -> dict:
    """Check #7: HostingProviderIPList overridden to Allow (dangerous). The rule
    group's scope-down limits which requests the Allow can apply to."""
    for r in rules:
        mg = r.get("managed")
        if not mg:
            continue
        for override in mg.get("overrides", []):
            if override.get("rule_name") == "HostingProviderIPList" and override.get("action") == "allow":
                sd = r.get("scope_down")
                return {"status": "FAIL",
                        "finding": f"HostingProviderIPList overridden to Allow in {r['name']} (priority {r['priority']}). "
                                   f"Cloud-hosted attack traffic bypasses all subsequent rules. Override to Count instead.",
                        "rule": r["name"], "priority": r["priority"],
                        "scope_down": sd["summary"] if sd else None,
                        "path_scoped": bool(sd) and _has_uri_constraint(sd.get("leaves", []))}
    return {"status": "PASS", "finding": None}


def _check_duplicate_rules(rules: list) -> dict:
    """Rules identical in everything but name and priority. The later copy of
    each group never changes the outcome."""
    groups = {}
    for r in sorted(rules, key=lambda r: r["priority"]):
        sd = r.get("scope_down") or {}
        key = json.dumps([r["type"], r["action"], sorted(r.get("rule_labels", [])),
                          r.get("statement", {}).get("summary"), r.get("statement", {}).get("leaves"),
                          sd.get("summary"), sd.get("leaves"),
                          r.get("rate_based"), r.get("managed")], sort_keys=True)
        groups.setdefault(key, []).append(_ref(r))
    dups = [g for g in groups.values() if len(g) > 1]
    if dups:
        return {"status": "FAIL", "groups": dups,
                "finding": f"{len(dups)} groups of identical rules: " +
                           "; ".join(" / ".join(x["name"] for x in g) for g in dups)}
    return {"status": "PASS", "finding": None}

def _check_uri_fragment_fallback(rules: list) -> dict:
    """UriFragment with FallbackBehavior MATCH: requests never carry a fragment,
    so the condition is always true and any path restriction is void."""
    flagged = []
    for r in rules:
        for l in _leaves(r, include_scope_down=True):
            if l["field"] == "uri_fragment" and l.get("fallback") == "MATCH" and not l["negated"]:
                flagged.append(dict(_ref(r), action=r["action"], match=l["match"], value=l["value"]))
                break
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "UriFragment conditions that always match: " +
                           ", ".join(f["name"] for f in flagged)}
    return {"status": "PASS", "finding": None}


def _check_uri_path_pitfalls(rules: list) -> dict:
    """URI path conditions that can never match as written: a literal '*' in a
    byte match (no wildcard support), or a query-string pattern on UriPath
    (UriPath excludes the query string)."""
    flagged = []
    for r in rules:
        problems = []
        for l in _leaves(r, include_scope_down=True):
            if l["field"] != "uri_path" or l["value"] is None:
                continue
            v = str(l["value"])
            if l["type"] == "byte_match":
                if "*" in v:
                    problems.append({"kind": "literal_wildcard", "value": v})
                if "?" in v:
                    problems.append({"kind": "query_in_path", "value": v})
            elif l["type"] == "regex_match" and re.search(r'\\\?|\[[^\]]*\?[^\]]*\]', v):
                problems.append({"kind": "query_in_path", "value": v})
        if problems:
            flagged.append(dict(_ref(r), action=r["action"], problems=problems))
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "URI path conditions that cannot match: " +
                           ", ".join(f["name"] for f in flagged)}
    return {"status": "PASS", "finding": None}


def _check_path_block_decoding(rules: list) -> dict:
    """Custom Block rules matching URI paths without URL decoding. WAF inspects
    the raw path, so percent-encoded variants of a blocked path slip through."""
    flagged = []
    for r in rules:
        if r["type"] != "custom" or r["action"] != "block":
            continue
        path = [l for l in _leaves(r) if l["field"] == "uri_path" and not l["negated"]
                and l["type"] in ("byte_match", "regex_match", "regex_pattern_set")]
        no_decode = [l for l in path if not DECODE_TRANSFORMS & set(l["transforms"])]
        if not no_decode:
            continue
        transforms = sorted({"+".join(l["transforms"]) or "NONE" for l in no_decode})
        case_sensitive = any(not CASE_TRANSFORMS & set(l["transforms"]) for l in no_decode)
        flagged.append(dict(_ref(r), transforms=transforms, case_sensitive=case_sensitive))
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "Path Block rules without URL_DECODE: " +
                           ", ".join(f["name"] for f in flagged)}
    return {"status": "PASS", "finding": None}


def _check_managed_count(rules: list) -> dict:
    """Managed rule groups set to Count as a whole, and content rules inside
    them overridden to Count."""
    groups, overrides = [], []
    for r in rules:
        mg = r.get("managed")
        if not mg:
            continue
        gn = mg.get("group_name", "")
        if r["action"] == "count":
            groups.append(dict(_ref(r), group=gn))
            continue
        if gn not in CONTENT_GROUPS:
            continue
        counted = [o["rule_name"] for o in mg.get("overrides", [])
                   if o.get("action") == "count" and o["rule_name"] not in ACCEPTED_COUNT_OVERRIDES]
        counted += [e for e in mg.get("excluded_rules", []) if e not in ACCEPTED_COUNT_OVERRIDES]
        if counted:
            overrides.append(dict(_ref(r), group=gn, overridden=counted))
    if groups or overrides:
        return {"status": "FAIL", "groups": groups, "overrides": overrides,
                "rules": groups + overrides,
                "finding": "Managed protections in Count: " +
                           ", ".join(x["name"] for x in groups + overrides)}
    return {"status": "PASS", "finding": None}


def _check_bot_control_config(rules: list) -> dict:
    """TGT_* overrides configured while Bot Control runs at COMMON level: those
    rules only exist at TARGETED, so the overrides do nothing."""
    for r in rules:
        mg = r.get("managed")
        if not mg or "BotControl" not in mg.get("group_name", ""):
            continue
        level = (mg.get("config") or {}).get("inspection_level", "COMMON")
        tgt = [o["rule_name"] for o in mg.get("overrides", []) if o["rule_name"].startswith("TGT_")]
        if level == "COMMON" and tgt:
            return {"status": "FAIL", "rule": r["name"], "priority": r["priority"],
                    "tgt_overrides": tgt,
                    "finding": f"{len(tgt)} TGT_* overrides with InspectionLevel COMMON"}
    return {"status": "PASS", "finding": None}


def _label_producers(rules: list) -> list:
    """(label or namespace prefix, rule) pairs for everything that adds labels."""
    prefixes = LABELS["managed_label_prefixes"]
    token_groups = set(LABELS["token_label_producers"])
    producers = []
    for r in rules:
        for lbl in r.get("rule_labels", []):
            producers.append((lbl, r))
        mg = r.get("managed")
        if mg:
            gn = mg.get("group_name", "")
            producers += [(pfx, r) for pfx, g in prefixes.items() if g == gn]
            if gn in token_groups:
                producers.append(("awswaf:managed:token:", r))
        if r["action"] in ("challenge", "captcha"):
            producers.append(("awswaf:managed:token:", r))
    return producers


def _produces(label: str, key: str, scope: str) -> bool:
    if scope == "NAMESPACE":
        return label.startswith(key) or key.startswith(label)
    if label.endswith(":"):  # managed namespace prefix
        return key.startswith(label)
    return key == label or key.endswith(":" + label)


def _check_order_issues(web_acl: dict, rules: list) -> dict:
    """Check #18: ordering problems with real consequences among existing rules."""
    ordered = sorted(rules, key=lambda r: r["priority"])
    producers = _label_producers(ordered)
    issues = []

    # Label consumed before any rule that produces it
    for r in ordered:
        for l in _leaves(r, include_scope_down=True):
            if l["type"] != "label_match":
                continue
            makers = [p for lbl, p in producers
                      if p is not r and _produces(lbl, l["value"], l["match"])]
            if makers and all(p["priority"] > r["priority"] for p in makers):
                issues.append({"kind": "label_before_producer", "rule": _ref(r),
                               "label": l["value"], "producers": [_ref(p) for p in makers]})

    # IP block list evaluated after Allow rules
    # A block list is an IP set, optionally ANDed with host conditions
    allows = [r for r in ordered if r["action"] == "allow"]
    for r in ordered:
        leaves = _leaves(r)
        ips = [l for l in leaves if l["type"] == "ip_set" and not l["negated"]]
        rest = [l for l in leaves if l not in ips]
        if (r["action"] == "block" and ips
                and all(l["field"] == "single_header:host" and not l["negated"] for l in rest)
                and (not rest or r.get("statement", {}).get("summary", "").startswith("AND("))):
            before = [a for a in allows if a["priority"] < r["priority"]]
            if before:
                issues.append({"kind": "blocklist_after_allow", "rule": _ref(r),
                               "allows": [_ref(a) for a in before]})

    # Default-Block ACL: content inspection after Allow rules never sees allowed traffic
    if web_acl.get("default_action") == "block":
        for r in ordered:
            mg = r.get("managed")
            if not mg or mg.get("group_name") not in CONTENT_GROUPS or r["action"] == "count":
                continue
            before = [a for a in allows if a["priority"] < r["priority"]]
            if before:
                issues.append({"kind": "inspection_after_allow", "rule": _ref(r),
                               "group": mg["group_name"], "allows": [_ref(a) for a in before]})

    # Bot Control charges per inspected request; later blocking rules waste that
    bot = next((r for r in ordered if "BotControl" in (r.get("managed") or {}).get("group_name", "")), None)
    if bot:
        later = [r for r in ordered if r["priority"] > bot["priority"]
                 and r["action"] in ("block", "challenge", "captcha")
                 and not any(l["type"] == "label_match" and "bot-control" in str(l["value"])
                             for l in _leaves(r, include_scope_down=True))]
        if later:
            issues.append({"kind": "bot_control_not_last", "rule": _ref(bot),
                           "later": [_ref(x) for x in later]})

    if issues:
        involved = []
        for i in issues:
            if i["rule"] not in involved:
                involved.append(i["rule"])
        return {"status": "FAIL", "issues": issues, "rules": involved,
                "finding": f"{len(issues)} ordering issues: " +
                           ", ".join(sorted({i['kind'] for i in issues}))}
    return {"status": "PASS", "finding": None}

# ── Flags ─────────────────────────────────────────────────────────────────

def _flag_allow_rules(rules: list) -> list:
    """Flag all Allow rules with forgeability analysis."""
    flags = []
    for r in rules:
        if r["action"] != "allow":
            continue
        summary = r.get("statement", {}).get("summary", "")
        leaves = _leaves(r)
        forgeable, unforgeable = _classify_leaves(leaves)
        all_forgeable = len(unforgeable) == 0 and len(forgeable) > 0
        blast_radius = "path_scoped" if _has_uri_constraint(leaves) else "global"

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

        # Several regex objects exempt a URI if any of them matches, same as joining with |
        regex_str = "|".join(exempt) if isinstance(exempt, list) else str(exempt)
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


def main():
    if len(sys.argv) < 3:
        fatal("Usage: waf-pre-checks.py <output_dir> <input_file>")

    output_dir = sys.argv[1]
    input_file = sys.argv[2]
    summary_file = os.path.join(output_dir, "waf-summary.json")

    if not os.path.isfile(summary_file):
        fatal(f"waf-summary.json not found in {output_dir}")

    try:
        summary = json.loads(Path(summary_file).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        fatal(f"Failed to read {summary_file}: {e}")

    web_acl = summary.get("web_acl", {})
    rules = summary.get("rules", [])

    # Run pre-checks
    pre_checks = {
        "token_domain": _check_token_domain(web_acl),
        "managed_versions": _check_managed_versions(rules),
        "default_action_redundancy": _check_default_action_redundancy(web_acl, rules),
        "count_without_labels": _check_count_without_labels(rules),
        "challenge_on_post_api": _check_challenge_on_post_api(rules),
        "hosting_provider_allow": _check_hosting_provider_allow(rules),
        "uri_fragment_fallback": _check_uri_fragment_fallback(rules),
        "uri_path_pitfalls": _check_uri_path_pitfalls(rules),
        "path_block_decoding": _check_path_block_decoding(rules),
        "managed_count": _check_managed_count(rules),
        "bot_control_config": _check_bot_control_config(rules),
        "order_issues": _check_order_issues(web_acl, rules),
        "duplicate_rules": _check_duplicate_rules(rules),
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
        fatal(f"Failed to write {output_file}: {e}")

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
