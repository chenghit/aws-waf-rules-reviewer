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
import urllib.parse
from pathlib import Path
from waf_utils import fatal, work_path

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
# IP list groups whose default-Block rules shouldn't sit in Count either
IP_LIST_GROUPS = {"AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesAnonymousIpList"}
# Rule overrides to Count that are common, deliberate practice, or the default
ACCEPTED_COUNT_OVERRIDES = {"SizeRestrictions_BODY", "HostingProviderIPList", "AWSManagedIPDDoSList"}
# AWS does not version the IP reputation groups
UNVERSIONED_GROUPS = {"AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesAnonymousIpList"}
DECODE_TRANSFORMS = {"URL_DECODE", "URL_DECODE_UNI"}
NORMALIZE_TRANSFORMS = {"NORMALIZE_PATH", "NORMALIZE_PATH_WIN"}
# Cleanups that act on decoded text: before a decode they miss what it reveals
CLEANUP_TRANSFORMS = {"LOWERCASE", "UPPERCASE", "REMOVE_NULLS", "REPLACE_NULLS"} | NORMALIZE_TRANSFORMS
# A pattern that spells out percent-encoding inspects the raw request on purpose
RAW_ENCODING = re.compile(r"%(?:[0-9A-Fa-f]|[(\[])")
# Fields that pick which request is sent, not what it carries. Dropping a
# condition on them means attacking a different target, not skipping a check.
TARGET_FIELDS = {"uri_path", "single_header:host", "method"}
# Browser signals a Challenge can't be solved for (prefetch), exempted on purpose
BROWSER_SIGNAL_FIELDS = {"single_header:sec-purpose", "single_header:purpose", "single_header:x-purpose"}
RATE_IP_KEYS = {"ip", "forwarded_ip"}
REGEX_META = set(".^$*+?()[]{}|\\")
CASE_TRANSFORMS = {"LOWERCASE", "UPPERCASE"}

LABELS = json.loads((Path(__file__).parent / "managed-labels.json").read_text(encoding="utf-8"))
# Official User-Agent strings of common crawlers, to catch name patterns they never send
_UA_FILE = Path(__file__).parent / "crawler-uas.json"
CRAWLERS = {k: v for k, v in json.loads(_UA_FILE.read_text(encoding="utf-8")).items()
            if not k.startswith("_")} if _UA_FILE.exists() else {}
# Sensitive-file probe paths and the AWS managed rules that block each
_PROBE_DATA = json.loads((Path(__file__).parent / "sensitive-probes.json").read_text(encoding="utf-8"))
PROBES, PROBE_VERSIONS = _PROBE_DATA["probes"], _PROBE_DATA["versions"]


def _leaves(rule: dict, include_scope_down: bool = False, sets: bool = False) -> list:
    """The rule's match conditions. sets: a regex pattern set provided in
    Step 1b becomes one regex leaf per pattern, carrying the set's name."""
    leaves = list(rule.get("statement", {}).get("leaves", []))
    if include_scope_down and rule.get("scope_down"):
        leaves += rule["scope_down"].get("leaves", [])
    if sets:
        leaves = [x for l in leaves for x in (
            [dict(l, type="regex_match", match="REGEX", value=v, set_size=len(l["regexes"])) for v in l["regexes"]]
            if l["type"] == "regex_pattern_set" and l.get("regexes") else [l])]
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


def _is_forgeable(leaf: dict) -> bool:
    return leaf["type"] not in UNFORGEABLE_LEAF_TYPES and leaf["field"] not in UNFORGEABLE_FIELDS


def _branches(stmt: dict) -> list | None:
    """The statement's DNF branches as lists of leaves, None if not expanded."""
    b = stmt.get("branches")
    return None if b is None else [[stmt["leaves"][i] for i in br] for br in b]


def _attacker_branches(stmt: dict) -> list | None:
    """Branches any client can satisfy on its own: every condition is forgeable
    or negated (an attacker is outside an IP set), and at least one is forgeable."""
    branches = _branches(stmt)
    if branches is None:
        return None
    return [b for b in branches if any(_is_forgeable(l) for l in b)
            and all(_is_forgeable(l) or l["negated"] for l in b)]


def _has_uri_constraint(leaves: list) -> bool:
    """True if a non-negated URI path condition limits the rule to some paths.
    uri_path STARTS_WITH '/' matches all traffic, so it doesn't count."""
    return any(l["field"] == "uri_path" and not l["negated"]
               and not (l["match"] == "STARTS_WITH" and l["value"] == "/")
               for l in leaves)


def _path_scoped(stmt: dict, branches: list | None = None) -> bool:
    """True if every branch that can match is limited to some paths."""
    branches = branches or _branches(stmt)
    if branches is None:
        return _has_uri_constraint(stmt.get("leaves", []))
    return bool(branches) and all(_has_uri_constraint(b) for b in branches)


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
    unpinned, outdated, behind = [], [], []
    latest = LABELS["latest_versions"]
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
        elif m and gn in latest:
            top = tuple(int(x) for x in latest[gn]["version"].split("."))
            if (int(m.group(1)), int(m.group(2))) < top:
                behind.append(dict(_ref(r), group=gn, version=ver, latest=latest[gn]["version"],
                                   released=latest[gn]["released"]))
    if unpinned or outdated or behind:
        parts = [f"{u['name']}: {u['group']} not pinned (follows AWS default version)" for u in unpinned]
        parts += [f"{o['name']}: {o['group']} pinned to {o['version']}" for o in outdated + behind]
        return {"status": "FAIL", "finding": "; ".join(parts),
                "unpinned": unpinned, "outdated": outdated, "behind": behind,
                "rules": unpinned + outdated + behind}
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
    """Check #17a: custom Count rules without RuleLabels. Rate-based rules in
    Count are left out: tuning a threshold by its metrics is the usual reason."""
    flagged = []
    for r in rules:
        # A rule group rule the Web ACL sets to Count is an override, not a monitoring rule
        if (r["action"] == "count" and r["type"] == "custom"
                and "own_action" not in (r.get("group") or {}) and not r.get("rule_labels") and not (r.get("action_handling") or {}).get("insert_headers")):
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
                        "path_scoped": bool(sd) and _path_scoped(sd)}
    return {"status": "PASS", "finding": None}


def _check_duplicate_rules(rules: list) -> dict:
    """Rules identical in everything but name and priority. The later copy of
    each group never changes the outcome."""
    groups = {}
    for r in sorted(rules, key=lambda r: r["order"]):
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
        for l in _leaves(r, include_scope_down=True, sets=True):
            if l["field"] != "uri_path" or l["value"] is None:
                continue
            v = str(l["value"])
            if l["type"] == "byte_match":
                if "*" in v:
                    problems.append({"kind": "literal_wildcard", "value": v})
                if "?" in v:
                    problems.append({"kind": "query_in_path", "value": v})
            elif l["type"] == "regex_match" and re.search(r'\\\?|\[[^\]]*\?[^\]]*\]', v):
                problems.append({"kind": "query_in_path", "value": v, **({"set": l["set"]} if "set" in l else {})})
        if problems:
            flagged.append(dict(_ref(r), action=r["action"], problems=problems))
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "URI path conditions that cannot match: " +
                           ", ".join(f["name"] for f in flagged)}
    return {"status": "PASS", "finding": None}


def _decode_field(field: str) -> bool:
    """Fields the origin URL-decodes before acting on them."""
    return field in ("uri_path", "query_string", "all_query_arguments") or field.startswith("single_query_argument:")


def _decode_problems(leaf: dict) -> list:
    """Ways a condition sees a different string than the origin, judged from
    its transformations alone (when a request can't be simulated)."""
    t = leaf["transforms"]
    dec = [i for i, x in enumerate(t) if x in DECODE_TRANSFORMS]
    probs = ["none"] if not dec else ["once"] if len(dec) == 1 else []
    if dec and CLEANUP_TRANSFORMS & set(t[:dec[-1]]):
        probs.append("order")
    # `//admin` or `/x/../admin` don't start with `/admin`, but the origin may resolve them to it
    if leaf["field"] == "uri_path" and not NORMALIZE_TRANSFORMS & set(t) and (
            leaf["match"] in ("STARTS_WITH", "EXACTLY")
            or leaf["type"] == "regex_match" and str(leaf["value"]).startswith("^")):
        probs.append("normalize")
    if probs and not CASE_TRANSFORMS & set(t):
        probs.append("nocase")
    return probs


def _normalized(transforms: list) -> bool:
    """A path decoded and then normalized: `/a/%2e%2e/b` and `/a/../b` both become `/b`."""
    dec = [i for i, x in enumerate(transforms) if x in DECODE_TRANSFORMS]
    return bool(dec) and any(x in NORMALIZE_TRANSFORMS for x in transforms[dec[-1]:])


# ── Request simulation ────────────────────────────────────────────────────
# Text transformations as the AWS WAF Developer Guide describes them, enough to
# tell whether a rule matches a rewritten request. Anything else isn't simulated.

SIM_TRANSFORMS = {"NONE", "URL_DECODE", "URL_DECODE_UNI", "LOWERCASE", "UPPERCASE",
                  "REMOVE_NULLS", "REPLACE_NULLS", "NORMALIZE_PATH", "NORMALIZE_PATH_WIN"}
_UP, _LOW = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"


def _uni(m) -> str:
    """`%uHHHH`: full-width ASCII maps to ASCII; otherwise only the low byte is kept."""
    c = int(m.group(1), 16)
    return chr(c - 0xFEE0) if 0xFF01 <= c <= 0xFF5E else chr(c & 0xFF)


def _normalize_path(s: str) -> str:
    """Remove multiple slashes, `.` segments, and `..` segments not at the beginning."""
    out = []
    for seg in re.sub(r"/{2,}", "/", s).split("/"):
        if seg == ".":
            continue
        if seg == ".." and out and out[-1] not in ("", ".."):
            out.pop()
            continue
        out.append(seg)
    return "/".join(out) or "/"


def _transform(text: str, transforms: list) -> str | None:
    for t in transforms:
        if t not in SIM_TRANSFORMS:
            return None
        if t in DECODE_TRANSFORMS:
            if t == "URL_DECODE_UNI":
                text = re.sub(r"%u([0-9a-fA-F]{4})", _uni, text)
            text = urllib.parse.unquote(text, errors="replace")
        elif t == "LOWERCASE":
            text = text.translate(str.maketrans(_UP, _LOW))
        elif t == "UPPERCASE":
            text = text.translate(str.maketrans(_LOW, _UP))
        elif t in ("REMOVE_NULLS", "REPLACE_NULLS"):
            text = text.replace("\0", "" if t == "REMOVE_NULLS" else " ")
        elif t in NORMALIZE_TRANSFORMS:
            text = _normalize_path(text.replace("\\", "/") if t == "NORMALIZE_PATH_WIN" else text)
    return text


def _sim_leaf(leaf: dict, text: str) -> bool | None:
    """Whether a byte or regex condition matches text after its transformations.
    None when that can't be simulated."""
    t = _transform(text, leaf["transforms"])
    pats = leaf.get("regexes") if leaf["type"] == "regex_pattern_set" else [leaf["value"]]
    if t is None or pats is None or leaf["type"] not in ("byte_match", "regex_match", "regex_pattern_set"):
        return None
    for v in map(str, pats):
        if leaf["type"] == "byte_match":
            hit = {"CONTAINS": v in t, "EXACTLY": v == t, "STARTS_WITH": t.startswith(v), "ENDS_WITH": t.endswith(v),
                   "CONTAINS_WORD": re.search(r"(?<!\w)" + re.escape(v) + r"(?!\w)", t) is not None}.get(leaf["match"])
        else:
            try:
                hit = re.search(v, t) is not None
            except re.error:
                hit = None
        if hit is None:
            return None
        if hit:
            return True
    return False


def _sim_blocks(rule: dict, req: dict, forge: bool = False) -> bool:
    """Whether a rule matches a request carrying only the fields in req. Other
    positive conditions aren't met (a Host condition covers one site). Negated
    ones are (the client is outside the IP set, sends no API key), except, with
    forge, those on a field the client sets: an attacker sends the key to skip it."""
    for b in _branches(rule["statement"]) or []:
        if all((hit := _sim_leaf(l, req[l["field"]])) is not None and hit != l["negated"] if l["field"] in req
               else l["negated"] and not (forge and _is_forgeable(l)) for l in b):
            return True
    return False


def _blockers(rules: list) -> tuple[list, bool]:
    """Rules that block a matching request, and whether Core rule set's
    GenericLFI_URIPATH blocks path traversal such as `/foo/../.env` (Appendix I)."""
    blockers = [r for r in rules if r["type"] == "custom" and r["action"] == "block"]
    lfi = False
    for r in rules:
        mg = r.get("managed") or {}
        if mg.get("group_name") == "AWSManagedRulesCommonRuleSet" and r["action"] != "count":
            off = {o["rule_name"] for o in mg.get("overrides", []) if o.get("action") in ("count", "allow")}
            lfi = lfi or "GenericLFI_URIPATH" not in off | set(mg.get("excluded_rules", []))
    return blockers, lfi


def _blocked(req: dict, blockers: list, lfi: bool, forge: bool = True) -> bool:
    """Whether some rule blocks the request. forge: the client is an attacker
    who sends whatever header skips a rule, not a scanner."""
    path = req.get("uri_path", "")
    if lfi and re.search(r"/\.\.(/|$)", urllib.parse.unquote(urllib.parse.unquote(path))):
        return True
    return any(_sim_blocks(r, req, forge) for r in blockers)


def _gates(req: dict, blockers: list) -> list:
    """Rules that block the request for a plain client but not for one that sends
    the header they require, such as an API key: the request needs one first."""
    return [r["name"] for r in blockers if _sim_blocks(r, req) and not _sim_blocks(r, req, forge=True)]


def _literal(leaf: dict) -> str | None:
    """The string a byte condition, or a regex with no special characters, matches."""
    v = str(leaf["value"])
    if leaf["type"] == "byte_match":
        return v or None
    if leaf["type"] != "regex_match":
        return None
    core = re.sub(r"(\(/\|\$\)|/\?\$|\$)$", "", re.sub(r"^\^", "", v))
    if not re.fullmatch(r"(?:[^.^$*+?()\[\]{}|\\]|\\[./\-_~])+", core):
        return None
    return re.sub(r"\\(.)", r"\1", core)


def _ends_anchored(leaf: dict) -> bool:
    v = str(leaf["value"])
    return leaf["match"] in ("EXACTLY", "ENDS_WITH") or (
        leaf["type"] == "regex_match" and re.search(r"\$\)?$", v) is not None and ";" not in v)


def _enc(c: str) -> str:
    return "%%%02X" % ord(c)


def _variants(base: str, path: bool, anchored: bool) -> list:
    """(kind, request) pairs the origin may resolve to base."""
    out = []
    # Encode the first character a rule would key on: `/.git` → `/%2egit`, `/admin` → `/%61dmin`
    i = next((k for k, c in enumerate(base) if c.isalnum() or c in "-._~"), None)
    if i is not None:
        out += [("enc", base[:i] + _enc(base[i]) + base[i + 1:]),
                ("double", base[:i] + "%25" + _enc(base[i])[1:] + base[i + 1:])]
    a = next((k for k, c in enumerate(base) if c.isalpha()), None)
    if a is not None and base[a].islower():
        out += [("case", base[:a] + base[a].upper() + base[a + 1:]),
                ("case", base[:a] + _enc(base[a].upper()) + base[a + 1:])]
    if not path:
        return out
    j = base.find("/", 1)
    if j > 0:
        out.append(("slash", base[:j] + "%2F" + base[j + 1:]))
    out += [("collapse", "/" + base), ("collapse", "/." + base), ("collapse", "/a/.." + base),
            ("collapse", "/a/%2e%2e" + base), ("collapse", "/.." + base)]
    if anchored:
        out.append(("params", base.rstrip("/") + ";x=1"))
    return out


def _check_path_block_decoding(rules: list) -> dict:
    """Path and query conditions in Block rules that a rewritten request gets
    past: `/%69nternal/`, `//internal/`, `/internal;x=1`, or an exemption that
    `/.well-known/../` reaches through. Each rewrite is simulated against every
    Block rule in the Web ACL, so only the ones nothing blocks are reported.
    Conditions that can't be simulated are judged from their transformations."""
    blockers, lfi = _blockers(rules)
    flagged = []
    # Labels a Block rule acts on: a Count rule that adds one picks paths for it
    keys = [l for r in rules if r["action"] == "block"
            for l in _leaves(r, include_scope_down=True) if l["type"] == "label_match" and not l["negated"]]
    for r in rules:
        # Block rules, and rate limits whose scope-down picks the paths they count (in Count, they
        # count the wrong requests once switched to Block)
        if not ((r["type"] == "custom" and r["action"] == "block")
                or r["type"] == "rate_based"
                or (r["type"] == "custom" and r["action"] == "count" and any(
                    _produces(lbl, str(k["value"]), k["match"]) for lbl in r.get("rule_labels", []) for k in keys))):
            continue
        leaves = [l for l in _leaves(r, include_scope_down=True, sets=True)
                  if _decode_field(l["field"]) and l["type"] in ("byte_match", "regex_match", "regex_pattern_set")]
        open_, guessed, used = [], [], []
        for l in leaves:
            if l["negated"] or RAW_ENCODING.search(str(l["value"])):
                continue
            lit = _literal(l) if l["field"] in ("uri_path", "query_string") else None
            base = None if lit is None else lit if l["field"] != "uri_path" or lit.startswith("/") else "/" + lit
            # A pattern with no literal is tried on the sensitive files it matches
            bases = [base] if base and _sim_leaf(l, base) else [
                x for x in PROBES if _sim_leaf(l, x)][:3] if l["field"] == "uri_path" and lit is None else []
            if bases:
                found = [(k, v) for b in bases for k, v in _variants(b, l["field"] == "uri_path", _ends_anchored(l))
                         if _sim_leaf(l, v) is False and not _blocked({l["field"]: v}, blockers, lfi)]
                for k, v in found:  # one example of each kind is enough
                    if k not in {o["kind"] for o in open_}:
                        open_.append({"kind": k, "example": v, "gates": _gates({l["field"]: v}, blockers)})
                if found:
                    used.append(l)
            elif p := _decode_problems(l):
                guessed += [x for x in p if x not in guessed]
                used.append(l)
        # Exemptions (NOT conditions) on the path: `/.well-known/../.git/config` matches one
        exempt = []
        for l in leaves:
            if not (l["negated"] and l["field"] == "uri_path" and l["match"] in ("STARTS_WITH", "CONTAINS", "REGEX")):
                continue
            lit = _literal(l)
            if lit is None or not lit.startswith("/"):
                if not _normalized(l["transforms"]) and not str(l["value"]).endswith("$"):
                    exempt.append({"value": str(l["value"]), "example": None})
                continue
            # Paths the rule blocks: its own literal paths, or common sensitive files
            targets = [b for b in (_literal(x) for x in leaves if not x["negated"] and x["field"] == "uri_path") if b
                       and b.startswith("/")] or list(PROBES)
            ex = next((v for t in targets if _sim_blocks(r, {"uri_path": t})
                       for v in (lit.rstrip("/") + "/.." + t, lit.rstrip("/") + "/%2e%2e" + t)
                       if not _sim_blocks(r, {"uri_path": v}) and not _blocked({"uri_path": v}, blockers, lfi)), None)
            if ex:
                exempt.append({"value": lit, "example": ex, "gates": _gates({"uri_path": ex}, blockers)})
        if not open_ and not guessed and not exempt:
            continue
        flagged.append(dict(_ref(r), type=r["type"], fields=sorted({l["field"] for l in used}),
                            transforms=sorted({"+".join(l["transforms"]) or "NONE" for l in used}),
                            open=open_, problems=guessed, exempt=exempt))
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "Path or query rules that rewritten requests get past: " +
                           ", ".join(f["name"] for f in flagged)}
    return {"status": "PASS", "finding": None}


def _has_opaque_value(value: str) -> bool:
    """A random-looking value (hash, UUID, token, key): an intended secret, not
    an exemption. Token alphabet only, with both letters and digits."""
    return (len(value) >= 16 and bool(re.fullmatch(r"[A-Za-z0-9+/=_-]+", value))
            and bool(re.search(r"[0-9]", value)) and bool(re.search(r"[A-Za-z]", value)))


def _maybe_allow(r: dict) -> bool:
    """A rule group whose rules weren't provided may hold an Allow rule."""
    rg = r.get("rule_group")
    return bool(rg) and not rg["loaded"] and r["action"] == "rule_group"


def _allow_sources(rules: list) -> list:
    """Rules that can end evaluation with Allow: Allow rules, managed rule
    groups with a rule overridden to Allow, and rule groups not provided."""
    return [r for r in rules if r["action"] == "allow" or _maybe_allow(r) or any(
        o.get("action") == "allow" for o in (r.get("managed") or {}).get("overrides", []))]


def _format_regex(regex: str) -> bool:
    """A regex that checks a value's shape (`^[a-f0-9]{32}$`), not names (`googlebot`)."""
    return not re.search(r"[A-Za-z]{3}", re.sub(r"\\.|\[[^\]]*\]|\{[^}]*\}|\(\?[a-zA-Z]+\)", "", regex))


def _requirement(leaf: dict) -> bool:
    """A condition that asks whether a field is there (size > 0) or well formed,
    rather than whether it holds a fixed value or names a client."""
    if leaf["type"] == "size_constraint":
        return (leaf["match"], leaf["value"]) in (("GT", 0), ("GE", 1))
    if leaf["type"] == "regex_match":
        return _format_regex(str(leaf["value"]))
    if leaf["type"] == "regex_pattern_set":
        if leaf.get("regexes"):
            return all(_format_regex(x) for x in leaf["regexes"])
        # Contents not provided: go by what the header carries
        return bool(re.search(r"key|token|auth|secret|sign", leaf["field"]))
    return False


def _check_forgeable_exemptions(web_acl: dict, rules: list) -> dict:
    """Rules that skip requests carrying something any client can send, e.g. a
    scope-down NOT(body CONTAINS 'x') or NOT(User-Agent matches crawler names).
    Sending that value skips the protection on any path. On CloudFront the Host
    header picks the distribution's site; behind an ALB any Host reaches the
    default listener rule, so a Host exemption counts there."""
    targets = TARGET_FIELDS if web_acl.get("scope") != "REGIONAL" else TARGET_FIELDS - {"single_header:host"}
    default_block = web_acl.get("default_action") == "block"
    allows = _allow_sources(rules)
    copies = _duplicate_copies(rules)
    flagged = []
    for r in rules:
        if (r["type"] == "custom" and r["action"] == "allow") or r["name"] in copies:
            continue
        cond = _match_condition(r)
        branches = _branches(cond) if cond else None
        if not branches:
            continue
        # The request escapes when it breaks every branch; a free escape breaks
        # each branch through a negated condition the client can satisfy
        escapes = []
        for b in branches:
            # "Block on this host or path unless the header is there, or well formed" requires the
            # header; the backend checks its value (an API key), so sending one isn't skipping a
            # protection. A fixed value such as `X-Internal: true` is WAF-only access control
            required = all(l["negated"] or l["field"] in targets for l in b)
            ls = [l for l in b if l["negated"] and _is_forgeable(l) and l["field"] not in targets
                  and not _has_opaque_value(str(l["value"])) and not (required and _requirement(l))]
            if not ls:
                break
            escapes += [l for l in ls if (l["field"], l["match"], l["value"])
                        not in {(e["field"], e["match"], e["value"]) for e in escapes}]
        else:
            # What skipping it changes: nothing yet for a Count rule; nothing in a
            # default-Block ACL unless a later rule can still Allow the request
            if r["action"] == "count":
                # A Count+Label rule acts through its label: skipping it skips its consumers
                impact = "label" if r.get("rule_labels") else "count"
            elif default_block and not any(a["order"] > r["order"] for a in allows):
                impact = "default_block"
            elif all(l["field"] in BROWSER_SIGNAL_FIELDS for l in escapes):
                impact = "browser_signal"
            else:
                impact = "bypass"
            flagged.append(dict(_ref(r), type=r["type"], action=r["action"], impact=impact,
                                where="scope_down" if r["type"] != "custom" else "statement",
                                exemptions=[{"field": l["field"], "match": l["match"], "value": l["value"]}
                                            for l in escapes]))
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "Protections that skip requests carrying a forgeable value: " +
                           ", ".join(f["name"] for f in flagged)}
    return {"status": "PASS", "finding": None}


def _check_noop_overrides(rules: list) -> dict:
    """Managed rule overrides that set a rule to its default action."""
    known = LABELS["managed_rules"]
    special = known["rule_defaults"]
    flagged = []
    for r in rules:
        mg = r.get("managed") or {}
        rules_known = known.get(mg.get("group_name"), [])
        noop = [(o["rule_name"], o["action"]) for o in mg.get("overrides", [])
                if (o["rule_name"] in rules_known and o.get("action") ==
                    ("count" if o["rule_name"] in known["default_count"] else "block"))
                or special.get(o["rule_name"]) == o.get("action")]
        if noop:
            flagged.append(dict(_ref(r), group=mg["group_name"], overrides=[n for n, _ in noop],
                                actions=[a for _, a in noop]))
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "Overrides that set the default action: " + ", ".join(f["name"] for f in flagged)}
    return {"status": "PASS", "finding": None}


def _check_rate_limits(web_acl: dict, rules: list) -> dict:
    """Rate-based rules that act as Challenge/CAPTCHA (a client with a valid
    token passes however fast it sends), and rules whose count is shared by
    every client that matches: CONSTANT, or custom keys without the IP."""
    immunity = (web_acl.get("challenge_config") or {}).get("immunity_time") or 300
    copies = _duplicate_copies(rules)
    challenge, shared = [], []
    for r in rules:
        rb = r.get("rate_based")
        if not rb or r["action"] == "count" or r["name"] in copies:
            continue
        if r["action"] in ("challenge", "captcha"):
            own = (r.get("challenge_config") or {}).get("immunity_time")
            challenge.append(dict(_ref(r), action=r["action"], limit=rb["limit"],
                                  immunity=own or immunity))
        keys = rb.get("custom_keys") or []
        if rb["aggregate_key_type"] == "CONSTANT" or (
                rb["aggregate_key_type"] == "CUSTOM_KEYS" and not any(k.split(":")[0].split("[")[0] in RATE_IP_KEYS for k in keys)):
            # Scoped to a User-Agent: a deliberate budget per bot. It matters when the
            # bot is a search engine crawler, whose budget forged UAs can use up; for
            # AI and other bots that's their own problem, not an SEO one
            ua = any(l["field"] == "single_header:user-agent" and not l["negated"]
                     for l in (r.get("scope_down") or {}).get("leaves", []))
            search = _hits_search_crawler(r.get("scope_down"))
            if ua and not search:
                continue
            shared.append(dict(_ref(r), key=rb["aggregate_key_type"] if not keys else ", ".join(keys),
                               limit=rb["limit"], window=rb.get("evaluation_window_sec"), crawler_budget=ua))
    # An internet-facing ACL with no rate limit that acts per client IP
    per_ip = [r for r in rules if r.get("rate_based") and (
        r["rate_based"]["aggregate_key_type"] in ("IP", "FORWARDED_IP") or any(
            k.split(":")[0].split("[")[0] in RATE_IP_KEYS for k in r["rate_based"].get("custom_keys") or []))]
    # A limit scoped to some paths leaves every other path without one
    scoped_ip = [_ref(r) for r in per_ip if r["action"] != "count"
                 and r.get("scope_down") and _path_scoped(r["scope_down"])]
    no_ip = web_acl.get("default_action") == "allow" and not any(
        r["action"] != "count" and _ref(r) not in scoped_ip for r in per_ip)
    counted_ip = [_ref(r) for r in per_ip if r["action"] == "count"]
    if challenge or shared or no_ip:
        return {"status": "FAIL", "challenge": challenge, "shared": shared, "no_ip_limit": no_ip,
                "counted_ip": counted_ip, "scoped_ip": scoped_ip if no_ip else [],
                "rules": challenge + shared + counted_ip + (scoped_ip if no_ip else []),
                "finding": "; ".join(
                    (["Rate limits that token holders pass or that share one count: " +
                      ", ".join(dict.fromkeys(x["name"] for x in challenge + shared))] if challenge + shared else [])
                    + (["no per-IP rate limit"] if no_ip else []))}
    return {"status": "PASS", "finding": None}


def _check_unused_labels(rules: list) -> dict:
    """Labels a rule adds that no rule matches: a Count+Label rule that ends in nothing."""
    keys = [l for r in rules for l in _leaves(r, include_scope_down=True) if l["type"] == "label_match"]
    copies = _duplicate_copies(rules)
    flagged = []
    for r in rules:
        if r["name"] in copies:
            continue
        unused = [lbl for lbl in r.get("rule_labels", [])
                  if not any(_produces(lbl, str(k["value"]), k["match"]) for k in keys)]
        if unused:
            flagged.append(dict(_ref(r), action=r["action"], labels=unused))
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "Labels no rule matches: " + ", ".join(f["name"] for f in flagged)}
    return {"status": "PASS", "finding": None}


def _check_host_exclusions(rules: list) -> dict:
    """Hosts that many rules leave out with NOT(Host ...): a sign the host would be
    simpler on its own Web ACL, if it has its own distribution or load balancer."""
    hosts = {}
    for r in rules:
        for l in _leaves(r, include_scope_down=True):
            if l["field"] == "single_header:host" and l["negated"] and l["value"]:
                hosts.setdefault(str(l["value"]).lower(), {})[r["name"]] = _ref(r)
    flagged = [{"host": h, "rules": list(rs.values())} for h, rs in hosts.items() if len(rs) >= 3]
    if flagged:
        return {"status": "FAIL", "hosts": flagged, "rules": [x for f in flagged for x in f["rules"]],
                "finding": "Hosts excluded by 3+ rules: " + ", ".join(f["host"] for f in flagged)}
    return {"status": "PASS", "finding": None}


def _check_security_automations(rules: list) -> dict:
    """Rules or IP sets from Security Automations for AWS WAF, which AWS retires in December 2026."""
    flagged = [dict(_ref(r)) for r in rules if "SecurityAutomations" in r["name"] or any(
        "SecurityAutomations" in str(l["value"]) for l in _leaves(r, include_scope_down=True)
        if l["type"] in ("ip_set", "regex_pattern_set"))]
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "Security Automations resources: " + ", ".join(f["name"] for f in flagged)}
    return {"status": "PASS", "finding": None}


def _dead_patterns(leaf: dict) -> list:
    """Patterns that can never match because a LOWERCASE/UPPERCASE transform
    removed the letter case they spell out."""
    case = next((t for t in reversed(leaf["transforms"]) if t in CASE_TRANSFORMS), None)
    if not case or leaf["value"] is None or leaf["type"] not in ("byte_match", "regex_match"):
        return []
    wrong = r"[A-Z]" if case == "LOWERCASE" else r"[a-z]"
    if leaf["type"] == "byte_match":
        return [leaf["value"]] if re.search(wrong, str(leaf["value"])) else []
    regex = str(leaf["value"])
    if regex.startswith("(?i)"):
        return []
    dead = []
    for part in _split_regex_branches(regex):
        literal = re.sub(r"\\.|\[[^\]]*\]|\{[^}]*\}", "", part)  # escapes, classes, counts
        if re.search(wrong, literal):
            dead.append(part)
    return dead


def _apply_case(text: str, transforms: list) -> str:
    case = next((t for t in reversed(transforms) if t in CASE_TRANSFORMS), None)
    return text.lower() if case == "LOWERCASE" else text.upper() if case == "UPPERCASE" else text


def _leaf_matches(leaf: dict, text: str) -> bool:
    """Whether a byte or regex match leaf matches text, after its case transform."""
    text, v = _apply_case(text, leaf["transforms"]), str(leaf["value"])
    try:
        if leaf["type"] == "regex_match":
            return bool(re.search(v, text))
    except re.error:
        return False
    return {"CONTAINS": v in text, "EXACTLY": v == text, "STARTS_WITH": text.startswith(v),
            "ENDS_WITH": text.endswith(v)}.get(leaf["match"], False)


def _hits_search_crawler(scope: dict | None) -> bool:
    """A User-Agent scope-down that matches a search engine crawler's published UA."""
    ua = [l for l in (scope or {}).get("leaves", []) if l["field"] == "single_header:user-agent"
          and not l["negated"] and l["type"] in ("byte_match", "regex_match")]
    return any(_leaf_matches(l, u) for l in ua for info in CRAWLERS.values() for u in info.get("uas", []))


def _crawler_dead(leaf: dict, skip: list) -> list:
    """User-Agent patterns that name a known crawler but match none of the
    User-Agents it publishes, e.g. `bingbot.html` (Bingbot sends `bingbot.htm`),
    or a robots.txt-only token such as `googlebot-news`. (pattern, family, kind)."""
    if leaf["field"] != "single_header:user-agent" or leaf["value"] is None:
        return []
    if leaf["type"] == "regex_match":
        parts = _split_regex_branches(str(leaf["value"]))
    elif leaf["type"] == "byte_match" and leaf["match"] in ("CONTAINS", "EXACTLY", "STARTS_WITH", "ENDS_WITH"):
        parts = [str(leaf["value"])]
    else:
        return []
    out = []
    for part in parts:
        if part in skip:
            continue
        low = part.lower()
        for fam, info in CRAWLERS.items():
            robots = [t for t in info.get("robots_only", []) if t in low]
            # Judge a name only if some published UA carries it; the operator may not publish every UA
            named = [t for t in info.get("tokens", []) if t in low
                     and any(t in u.lower() for u in info.get("uas", []))]
            if not robots and not named:
                continue
            uas = [_apply_case(u, leaf["transforms"]) for u in info.get("uas", [])]
            try:
                if leaf["type"] == "regex_match":
                    hit = any(re.search(part, u) for u in uas)
                else:
                    hit = any({"CONTAINS": part in u, "EXACTLY": part == u,
                               "STARTS_WITH": u.startswith(part), "ENDS_WITH": u.endswith(part)}[leaf["match"]]
                              for u in uas)
            except re.error:
                break
            if not hit:
                out.append((part, fam, "robots" if robots else "ua"))
            break
    return out


def _check_dead_patterns(rules: list) -> dict:
    """Patterns no request can match: a letter case a LOWERCASE/UPPERCASE
    transform removed, or a crawler name the crawler doesn't send that way."""
    flagged = []
    for r in rules:
        for l in _leaves(r, include_scope_down=True, sets=True):
            dead = _dead_patterns(l)
            crawler = _crawler_dead(l, dead)
            if not dead and not crawler:
                continue
            total = 1 if l["type"] == "byte_match" else len(_split_regex_branches(str(l["value"])))
            flagged.append(dict(_ref(r), action=r["action"], field=l["field"], negated=l["negated"],
                                transform=next((t for t in reversed(l["transforms"]) if t in CASE_TRANSFORMS), None),
                                dead=dead, crawler=[{"pattern": p, "family": f, "kind": k} for p, f, k in crawler],
                                whole=len(dead) + len(crawler) >= total,
                                **({"set": l["set"], "set_size": l["set_size"]} if "set" in l else {})))
    # One dead pattern of a set doesn't stop the others; the set fails only if all of them are dead
    for f in flagged:
        if "set" in f:
            dead_all = [g for g in flagged if g["name"] == f["name"] and g.get("set") == f["set"]
                        and g["field"] == f["field"] and g["whole"]]
            f["whole_set"] = len(dead_all) >= f["set_size"]
    for f in flagged:
        if "set" in f:
            f["whole"] = f.pop("whole_set")
            del f["set_size"]
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "Patterns that can never match: " + ", ".join(dict.fromkeys(f["name"] for f in flagged))}
    return {"status": "PASS", "finding": None}


BROAD_FIELDS_SKIP = {"single_header:user-agent", "method"}  # short tokens are normal there


def _check_broad_regex(rules: list) -> dict:
    """Regex conditions on Block, Challenge, or CAPTCHA rules that match far
    more than they spell out: a top-level alternative that is a short word
    with no anchor (`open|day` matches anything containing `day`), or a
    character class written as a sequence (`[\\%20]` is one of `%`, `2`, `0`)."""
    flagged = []
    for r in rules:
        # A rule group rule the Web ACL overrides to Count blocks again once the override goes
        own = (r.get("group") or {}).get("own_action")
        if r["type"] != "custom" or (own or r["action"]) not in ("block", "challenge", "captcha"):
            continue
        for l in _leaves(r, sets=True):
            if l["type"] != "regex_match" or l["negated"] or l["field"] in BROAD_FIELDS_SKIP:
                continue
            regex = str(l["value"])
            parts = _split_regex_branches(re.sub(r"^\(\?[a-zA-Z]+\)", "", regex))  # drop a leading (?i)
            # An encoded byte such as `%00` is meant to match anywhere
            short = [b for b in parts if b and not set(b) & REGEX_META and len(b) <= 4
                     and not re.fullmatch(r"(?:%[0-9A-Fa-f]{2})+", b)] if len(parts) > 1 else []
            classes = [(c, m) for c in dict.fromkeys(re.findall(r"(?<!\\)\[(?:\\.|[^\]\\])*\]", regex))
                       for m in re.findall(r"%[0-9A-Fa-f]{2}", c.replace("\\", ""))[:1]]
            if short or classes:
                flagged.append(dict(_ref(r), action=r["action"], overridden=bool(own), field=l["field"], regex=regex, short=short,
                                    classes=[{"cls": c, "seq": m} for c, m in classes],
                                    **({"set": l["set"]} if "set" in l else {})))
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "Regex conditions broader than written: " + ", ".join(dict.fromkeys(f["name"] for f in flagged))}
    return {"status": "PASS", "finding": None}


def _check_sensitive_files(web_acl: dict, rules: list) -> dict:
    """Default-Allow Web ACLs that let sensitive-file probes such as
    `/.git/config` through: no deployed managed rule blocks the path (per
    sensitive-probes.json), and no custom Block rule matches it."""
    if web_acl.get("default_action") != "allow":
        return {"status": "PASS", "finding": None}
    active = set()  # (group, rule) pairs that block
    for r in rules:
        mg = r.get("managed") or {}
        if not mg or r["action"] == "count":
            continue
        # Coverage was recorded at PROBE_VERSIONS; an older pinned version may not block
        m = re.search(r"(\d+)\.(\d+)", mg.get("version", ""))
        rec = PROBE_VERSIONS.get(mg.get("group_name"))
        if m and rec and (int(m.group(1)), int(m.group(2))) < tuple(int(x) for x in rec.split(".")):
            continue
        off = {o["rule_name"] for o in mg.get("overrides", []) if o.get("action") in ("count", "allow")}
        active |= {(mg.get("group_name", ""), x) for p in PROBES.values() for g, x in p
                   if g == mg.get("group_name") and x not in off | set(mg.get("excluded_rules", []))}
    blockers, _ = _blockers(rules)
    open_paths = [p for p, by in PROBES.items() if not any(tuple(x) in active for x in by)
                  and not _blocked({"uri_path": p}, blockers, False, forge=False)]
    if not open_paths:
        return {"status": "PASS", "finding": None}
    groups = {(r.get("managed") or {}).get("group_name") for r in rules}
    # Recommend the Linux group only if it would block an open path and isn't deployed yet
    linux_helps = "AWSManagedRulesLinuxRuleSet" not in groups and any(
        g == "AWSManagedRulesLinuxRuleSet" for p in open_paths for g, _ in PROBES[p])
    return {"status": "FAIL", "paths": open_paths, "linux_helps": linux_helps,
            "dotfiles_open": any(seg.startswith(".") for p in open_paths for seg in p.split("/")),
            "managed_gaps": [p for p in open_paths if not PROBES[p]],
            "finding": "Sensitive-file probes not blocked: " + ", ".join(open_paths)}


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
        if gn not in CONTENT_GROUPS | IP_LIST_GROUPS:
            continue
        counted = [o["rule_name"] for o in mg.get("overrides", [])
                   if o.get("action") == "count" and o["rule_name"] not in ACCEPTED_COUNT_OVERRIDES]
        counted += [e for e in mg.get("excluded_rules", []) if e not in ACCEPTED_COUNT_OVERRIDES]
        if counted:
            # Rules of the latest version still blocking; empty means the group only labels
            known = LABELS["managed_rules"].get(gn, [])
            over = {o["rule_name"]: o.get("action") for o in mg.get("overrides", [])}
            over.update({e: "count" for e in mg.get("excluded_rules", [])})
            left = [x for x in known if over.get(
                x, "count" if x in LABELS["managed_rules"]["default_count"] else "block") in ("block", "challenge", "captcha")]
            overrides.append(dict(_ref(r), group=gn, overridden=counted, group_versioned=gn not in UNVERSIONED_GROUPS,
                                  still_blocking=left if known and len(left) <= 2 else None))
    if groups or overrides:
        return {"status": "FAIL", "groups": groups, "overrides": overrides,
                "rules": groups + overrides,
                "finding": "Managed protections in Count: " +
                           ", ".join(x["name"] for x in groups + overrides)}
    return {"status": "PASS", "finding": None}


def _check_rule_group_count(rules: list) -> dict:
    """Rule group references set to Count by the Web ACL: the whole group
    (OverrideAction Count), or some of its rules (RuleActionOverrides)."""
    flagged = []
    for r in rules:
        rg = r.get("rule_group")
        if not rg:
            continue
        counted = [o["rule_name"] for o in rg["overrides"] if o["action"] == "count"] + rg["excluded_rules"]
        if r["action"] == "count" or counted:
            flagged.append(dict(_ref(r), group=rg["name"], whole=r["action"] == "count", overridden=counted))
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "Rule groups set to Count: " + ", ".join(f["name"] for f in flagged)}
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


def _check_bot_control_inert(rules: list) -> dict:
    """Bot Control with every rule that would act overridden to Count, and no
    rule matching its labels: it's billed per request and changes nothing."""
    bc = LABELS["bot_control_rules"]
    used = any(l["type"] == "label_match" and str(l["value"]).startswith("awswaf:managed:aws:bot-control")
               for r in rules for l in _leaves(r, include_scope_down=True))
    flagged = []
    for r in rules:
        mg = r.get("managed") or {}
        # A whole-group Count is reported as a managed group in Count
        if used or "BotControl" not in mg.get("group_name", "") or r["action"] == "count":
            continue
        level = (mg.get("config") or {}).get("inspection_level", "COMMON")
        names = bc["common"] + (bc["targeted"] if level == "TARGETED" else [])
        m = re.search(r"(\d+)\.(\d+)", mg.get("version", ""))
        if m and int(m.group(1)) < 5:
            names = [n for n in names if n not in bc["since_5_0"]]
        off = {o["rule_name"] for o in mg.get("overrides", []) if o.get("action") == "count"} | set(mg.get("excluded_rules", []))
        acting = [n for n in names if n not in off and n not in bc["count_default"]]
        # Unpinned, only the 5.0 rules left: they act only if the default is 5.0 or later
        if not acting or (not m and set(acting) <= set(bc["since_5_0"])):
            flagged.append(dict(_ref(r), level=level, counted=len(off & set(names)), remaining=acting,
                                scoped=bool(r.get("scope_down"))))
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "Bot Control with every acting rule in Count and no label consumer: " +
                           ", ".join(f["name"] for f in flagged)}
    return {"status": "PASS", "finding": None}


def _check_unknown_overrides(rules: list) -> dict:
    """Bot Control overrides that name no rule in the group, such as
    `TGT_TokenReuseIp`, which Version_2.0 replaced with Low, Medium, and High rules."""
    bc = LABELS["bot_control_rules"]
    known = set(bc["common"] + bc["targeted"])
    flagged = []
    for r in rules:
        mg = r.get("managed") or {}
        if "BotControl" not in mg.get("group_name", ""):
            continue
        common = (mg.get("config") or {}).get("inspection_level", "COMMON") == "COMMON"
        # At COMMON, TGT_* overrides are reported as doing nothing already
        unknown = [o["rule_name"] for o in mg.get("overrides", []) if o["rule_name"] not in known
                   and not (common and o["rule_name"].startswith("TGT_"))]
        if unknown:
            m = re.search(r"(\d+)\.(\d+)", mg.get("version", ""))
            flagged.append(dict(_ref(r), names=unknown, pinned=bool(m)))
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "Bot Control overrides naming no rule: " + ", ".join(n for f in flagged for n in f["names"])}
    return {"status": "PASS", "finding": None}


def _check_duplicate_metrics(rules: list) -> dict:
    """Web ACL rules that share a CloudWatch metric name."""
    seen = {}
    copies = _duplicate_copies(rules)  # reported as duplicate rules already
    for r in rules:
        if r.get("group") or r.get("firewall_manager") or r["name"] in copies:
            continue
        m = (r.get("visibility_config") or {}).get("metric_name")
        if m:
            seen.setdefault(m, []).append(_ref(r))
    dup = [{"metric": m, "rules": rs} for m, rs in seen.items() if len(rs) > 1]
    if dup:
        return {"status": "FAIL", "metrics": dup, "rules": [x for d in dup for x in d["rules"]],
                "finding": "Rules sharing a metric name: " + ", ".join(d["metric"] for d in dup)}
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
                producers += [(pfx, r) for pfx in LABELS["token_label_prefixes"]]
        # A rule group whose rules weren't provided may add anything in its namespace
        rg = r.get("rule_group")
        if rg and not rg["loaded"]:
            producers.append((rg["label_namespace"], r))
        # AWS documents token labels only for the groups above; a Challenge or
        # CAPTCHA action may add them too, so don't call such labels unreachable
        if r["action"] in ("challenge", "captcha"):
            producers += [(pfx, r) for pfx in LABELS["token_label_prefixes"]]
    return producers


def _produces(label: str, key: str, scope: str) -> bool:
    if scope == "NAMESPACE":
        return label.startswith(key) or key.startswith(label)
    if label.endswith(":"):  # managed namespace prefix
        return key.startswith(label)
    return key == label or key.endswith(":" + label)


def _duplicate_copies(rules: list) -> set:
    """Names of the later copies of identical rules, reported by the duplicate check."""
    return {x["name"] for g in _check_duplicate_rules(rules).get("groups", []) for x in g[1:]}


def _label_may_come_from_elsewhere(key: str, rules: list) -> bool:
    """True if a label nobody in this ACL adds could still come from a source
    the scripts can't see: a rule group whose rules weren't provided, or a
    managed group whose label namespace isn't in managed-labels.json."""
    known = set(LABELS["managed_label_prefixes"].values()) | set(LABELS["token_label_producers"])
    for r in rules:
        if r.get("rule_group") and not r["rule_group"]["loaded"]:
            return True
        mg = r.get("managed")
        if mg and key.startswith("awswaf:managed:") and mg.get("group_name") not in known:
            return True
    return False


def _match_condition(rule: dict) -> dict | None:
    """The condition a request must meet for the rule to act on it: the
    scope-down for rate-based and managed rules, the statement otherwise."""
    if rule["type"] in ("rate_based", "managed_rule_group"):
        return rule.get("scope_down")
    return rule.get("statement")


def _contains_literals(leaf: dict, partial: bool = False) -> list | None:
    """Substrings of which the leaf matches any one, for a CONTAINS byte match
    or an unanchored regex of plain alternatives; None for anything else.
    partial: keep just the plain alternatives of a regex that also has others.
    Containing one of those still means the regex matches."""
    if leaf["type"] == "byte_match" and leaf["match"] == "CONTAINS":
        return [str(leaf["value"])]
    if leaf["type"] == "regex_match":
        parts = _split_regex_branches(str(leaf["value"]))
        plain = [p for p in parts if p and not (set(p) & REGEX_META)]
        if len(plain) == len(parts) or (partial and plain):
            return plain
    return None


def _leaf_implies(b: dict, a: dict) -> bool:
    """Every request matching leaf b also matches leaf a."""
    if (b["field"], b["transforms"], b["negated"]) != (a["field"], a["transforms"], a["negated"]):
        return False
    if (b["type"], b["match"], b["value"]) == (a["type"], a["match"], a["value"]):
        return True
    if b["negated"]:
        return False
    need = _contains_literals(a, partial=True)
    if need is None:
        return False
    have = _contains_literals(b)
    if have is None and b["type"] == "byte_match" and b["match"] in ("EXACTLY", "STARTS_WITH", "ENDS_WITH"):
        have = [str(b["value"])]
    return have is not None and all(any(n in h for n in need) for h in have)


def _branch_implies(b: list, a: list) -> bool:
    """Every request meeting all of branch b also meets all of branch a."""
    return bool(a) and all(any(_leaf_implies(lb, la) for lb in b) for la in a)


def _gate_miss(rule: dict, gate: dict) -> str | None:
    """Why a managed rule group can't add a version-gated label: "level",
    "version", or "unpinned" (runs AWS's default version). None if it can."""
    mg = rule.get("managed") or {}
    if (mg.get("config") or {}).get("inspection_level", "COMMON") != gate["level"]:
        return "level"
    m = re.search(r'(\d+)\.(\d+)', mg.get("version", ""))
    if not m:
        return "unpinned"
    if (int(m.group(1)), int(m.group(2))) < tuple(int(x) for x in gate["min_version"].split(".")):
        return "version"
    return None


def _check_order_issues(web_acl: dict, rules: list) -> dict:
    """Check #18: ordering problems with real consequences among existing rules."""
    ordered = sorted(rules, key=lambda r: r["order"])
    producers = _label_producers(ordered)
    issues = []

    # Label consumed before any rule that produces it
    for r in ordered:
        for l in _leaves(r, include_scope_down=True):
            if l["type"] != "label_match":
                continue
            if l["value"] in LABELS["label_case"]:
                issues.append({"kind": "label_wrong_case", "rule": _ref(r), "label": l["value"],
                               "fixed": LABELS["label_case"][l["value"]]})
                continue
            makers = [p for lbl, p in producers
                      if p is not r and _produces(lbl, l["value"], l["match"])]
            gate = next((g for pfx, g in LABELS["version_gated_labels"].items()
                         if not pfx.startswith("_") and l["value"].startswith(pfx)), None)
            earlier = [p for p in makers if p["order"] < r["order"]]
            if makers and not earlier:
                issues.append({"kind": "label_before_producer", "rule": _ref(r),
                               "label": l["value"], "producers": [_ref(p) for p in makers]})
            elif gate and earlier and all(_gate_miss(p, gate) for p in earlier):
                issues.append({"kind": "label_not_emitted", "rule": _ref(r), "label": l["value"],
                               "level": gate["level"], "min_version": gate["min_version"],
                               "producers": [dict(_ref(p), reason=_gate_miss(p, gate)) for p in earlier]})
            elif not makers and not _label_may_come_from_elsewhere(l["value"], ordered):
                issues.append({"kind": "label_no_producer", "rule": _ref(r), "label": l["value"]})

    # Rules that no request reaches: an earlier Allow or Block ends every match.
    # Later copies of identical rules are the duplicate check's finding.
    copies = _duplicate_copies(rules)
    for i, r in enumerate(ordered):
        if r["name"] in copies:
            continue
        cond = _match_condition(r)
        branches = _branches(cond) if cond else None
        if not branches or any(not b for b in branches):
            continue
        earlier = [a for a in ordered[:i] if a["type"] == "custom" and a["action"] in ("allow", "block")]
        stoppers = []
        for b in branches:
            a = next((a for a in earlier if any(_branch_implies(b, ab) for ab in _branches(a["statement"]) or [])), None)
            if not a:
                break
            if a not in stoppers:
                stoppers.append(a)
        else:
            issues.append({"kind": "unreachable", "rule": _ref(r), "rule_action": r["action"],
                           "stoppers": [_ref(a) for a in stoppers],
                           "actions": sorted({a["action"] for a in stoppers})})

    # IP block list evaluated after Allow rules
    # Anything that can end evaluation with Allow: Allow rules, and managed
    # rule groups with a rule overridden to Allow
    allows = []
    for r in ordered:
        if r["action"] == "allow":
            allows.append(r)
            continue
        over = [o["rule_name"] for o in (r.get("managed") or {}).get("overrides", [])
                if o.get("action") == "allow"]
        if over:
            allows.append(dict(r, name=f"{r['name']} ({', '.join(over)} → Allow)"))

    # A block list is an IP set, optionally ANDed with host conditions
    for r in ordered:
        leaves = _leaves(r)
        ips = [l for l in leaves if l["type"] == "ip_set" and not l["negated"]]
        rest = [l for l in leaves if l not in ips]
        if (r["action"] == "block" and ips
                and all(l["field"] == "single_header:host" and not l["negated"] for l in rest)
                and (not rest or r.get("statement", {}).get("summary", "").startswith("AND("))):
            # A trusted-IP allow list first is the recommended order (Appendix D), not a gap
            before = [a for a in allows if a["order"] < r["order"] and not (_branches(a.get("statement", {})) and all(
                any(l["type"] == "ip_set" and not l["negated"] for l in br) for br in _branches(a["statement"])))]
            if before:
                issues.append({"kind": "blocklist_after_allow", "rule": _ref(r),
                               "allows": [_ref(a) for a in before]})

    # Default-Block ACL: content inspection after Allow rules never sees allowed traffic
    if web_acl.get("default_action") == "block":
        for r in ordered:
            mg = r.get("managed")
            if not mg or mg.get("group_name") not in CONTENT_GROUPS or r["action"] == "count":
                continue
            before = [a for a in allows if a["order"] < r["order"]]
            if before:
                issues.append({"kind": "inspection_after_allow", "rule": _ref(r),
                               "group": mg["group_name"], "allows": [_ref(a) for a in before]})

    # Default-Block ACL: after the last Allow, every request ends in Block anyway.
    # A rule group whose rules weren't provided may Allow, so it counts here
    maybe = allows + [r for r in ordered if _maybe_allow(r)]
    if web_acl.get("default_action") == "block" and maybe:
        last = max(a["order"] for a in maybe)
        inert = [r for r in ordered if r["order"] > last and not (
            (r.get("managed") or {}).get("group_name") in CONTENT_GROUPS and r["action"] != "count")]
        for x in inert:
            issues.append({"kind": "after_last_allow", "rule": _ref(x), "later": [_ref(y) for y in inert]})

    # Bot Control charges per inspected request; later blocking rules waste that
    bot = next((r for r in ordered if "BotControl" in (r.get("managed") or {}).get("group_name", "")), None)
    if bot:
        later = [r for r in ordered if r["order"] > bot["order"]
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
                "finding": "Ordering issues: " +
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
        attack = _attacker_branches(r["statement"])
        safe, path_branches = [], []
        if attack is None:
            all_forgeable = len(unforgeable) == 0 and len(forgeable) > 0
            blast_radius = "path_scoped" if _has_uri_constraint(leaves) else "global"
        else:
            # One forgeable branch of an OR is enough, whatever the other branches check
            all_forgeable = bool(attack)
            if attack:
                # Fields an attacker sets on any path; path-scoped branches are listed apart
                wide = [b for b in attack if not _has_uri_constraint(b)] or attack
                forgeable = [f for f in _classify_leaves([l for b in wide for l in b])[0] if f not in TARGET_FIELDS] \
                    or _classify_leaves([l for b in wide for l in b])[0]
                # Path-only branches let every request to the path through; others need forged content
                path_branches = [{"paths": [l["value"] for l in b if l["field"] == "uri_path" and not l["negated"]],
                                  "forged": any(_is_forgeable(l) and l["field"] not in TARGET_FIELDS for l in b),
                                  "prefix_unnormalized": any(
                                      l["field"] == "uri_path" and l["match"] == "STARTS_WITH"
                                      and not _normalized(l["transforms"]) for l in b)}
                                 for b in attack if _has_uri_constraint(b)] if wide is not attack else []
                # Unforgeable conditions in the branches an attacker can't satisfy
                safe = _classify_leaves([l for b in _branches(r["statement"]) if b not in attack
                                         for l in b if not l["negated"]])[1]
            blast_radius = "path_scoped" if _path_scoped(r["statement"], attack or None) else "global"

        flags.append({
            "name": r["name"],
            "priority": r["priority"],
            "statement_summary": summary,
            "forgeable_conditions": forgeable,
            "unforgeable_conditions": unforgeable,
            "safe_conditions": safe,
            "path_branches": path_branches,
            # STARTS_WITH path branches without NORMALIZE_PATH also match /prefix/../elsewhere
            "prefix_unnormalized": any(l["field"] == "uri_path" and l["match"] == "STARTS_WITH"
                                       and not _normalized(l["transforms"])
                                       for b in (attack or []) for l in b),
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
    """Flag AntiDDoS AMR exempt URI regex branches with anchoring analysis. AWS
    WAF matches them against the host followed by the normalized path, so `^/`
    never matches and an unanchored path branch matches anywhere."""
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
                "path_anchored": b.startswith(("^/", "^\\/")),
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
    summary_file = work_path(output_dir, "waf-summary.json")

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
        "sensitive_files": _check_sensitive_files(web_acl, rules),
        "managed_count": _check_managed_count(rules),
        "bot_control_config": _check_bot_control_config(rules),
        "bot_control_inert": _check_bot_control_inert(rules),
        "unknown_overrides": _check_unknown_overrides(rules),
        "duplicate_metrics": _check_duplicate_metrics(rules),
        "rule_group_count": _check_rule_group_count(rules),
        "order_issues": _check_order_issues(web_acl, rules),
        "duplicate_rules": _check_duplicate_rules(rules),
        "forgeable_exemptions": _check_forgeable_exemptions(web_acl, rules),
        "dead_patterns": _check_dead_patterns(rules),
        "broad_regex": _check_broad_regex(rules),
        "noop_overrides": _check_noop_overrides(rules),
        "rate_limits": _check_rate_limits(web_acl, rules),
        "unused_labels": _check_unused_labels(rules),
        "security_automations": _check_security_automations(rules),
        "host_exclusions": _check_host_exclusions(rules),
    }

    # Build flags
    flags = {
        "allow_rules": _flag_allow_rules(rules),
        "scope_downs": _flag_scope_downs(rules),
        "exempt_regex_branches": _flag_exempt_regex(rules),
    }

    result = {"pre_checks": pre_checks, "flags": flags}

    # Write output
    output_file = work_path(output_dir, "pre-checks.json")
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
