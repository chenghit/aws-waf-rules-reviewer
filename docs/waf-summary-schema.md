# waf-summary.json Schema Definition

Version: 1.0

This is the central intermediate file consumed by all downstream scripts and LLM analysis.

## Top-level Structure

```json
{
  "schema_version": "1.0",
  "input_file": "waf-rules.json",
  "input_format": "aws_cli | console_export | snake_case_custom",
  "web_acl": {
    "name": "example-prod",
    "id": "e37e78b0-...",
    "arn": "<ARN>",
    "description": "...",
    "default_action": "allow | block",
    "default_action_custom_handling": true | false,
    "capacity": 435,
    "token_domains": ["example.com", "www.example.com"],
    "challenge_config": {
      "immunity_time": 300
    },
    "captcha_config": {
      "immunity_time": 300
    }
  },
  "rule_count": 16,
  "rules": [ "...see Rule Object below..." ]
}
```

Notes:
- `capacity` may be null if not present in the input JSON (Console export includes it, some formats don't)
- `token_domains` may be null or empty array
- `challenge_config` / `captcha_config` are Web ACL level defaults; may be null
- `default_action_custom_handling`: true if default_action contains CustomRequestHandling or CustomResponseBodies

## Rule Object

Every rule in the `rules` array has this structure:

```json
{
  "name": "AWS-AWSManagedRulesAntiDDoSRuleSet",
  "priority": 0,
  "type": "managed_rule_group | custom | rate_based",
  "action": "allow | block | count | challenge | captcha | managed_default",
  "rule_labels": ["crawler:verified"],
  "visibility_config": {
    "metric_name": "...",
    "sampled_requests_enabled": true,
    "cloudwatch_metrics_enabled": true
  },
  "statement_summary": "managed: AWS/AWSManagedRulesAntiDDoSRuleSet v1.0",
  "source": {
    "lines": [3, 45],
    "jsonpath": "$.WebACL.Rules[0]"
  },

  // --- Managed rule group fields (only when type == "managed_rule_group") ---
  "managed": {
    "vendor": "AWS",
    "group_name": "AWSManagedRulesAntiDDoSRuleSet",
    "version": "Version_1.0",
    "overrides": [
      {"rule_name": "ChallengeAllDuringEvent", "action": "count"}
    ],
    "excluded_rules": [],
    "config": {
      // AntiDDoS AMR specific
      "sensitivity_to_block": "LOW",
      "sensitivity_to_challenge": "HIGH",
      "uris_exempt_from_challenge": "\\/query|\\/api\\/|\\.(css|js|png)$"
    }
  },

  // --- Rate-based fields (only when type == "rate_based") ---
  "rate_based": {
    "limit": 100,
    "evaluation_window_sec": 60,
    "aggregate_key_type": "IP | FORWARDED_IP | CUSTOM_KEYS",
    "scope_down": {
      "summary": "host EXACTLY 'www.example.com'",
      "source_lines": [500, 520]
    }
  },

  // --- Scope-down (for managed rule groups and rate-based rules) ---
  "scope_down": {
    "summary": "URI EXACTLY '/'",
    "source_lines": [30, 40]
  },

  // --- Challenge/CAPTCHA config override at rule level ---
  "challenge_config": {
    "immunity_time": 14400
  },

  // --- Custom rule statement details ---
  "statement": {
    "summary": "AND(NOT(URI CONTAINS '/ScriptResource.axd'), NOT(URI CONTAINS '/CMSPages/GetResource.ashx'))",
    "leaf_count": 2,
    "leaf_types": ["byte_match"],
    "samples": null
  }
}
```

## Field Details

### action
- `"allow"`, `"block"`, `"count"`, `"challenge"`, `"captcha"`: self-explanatory
- `"managed_default"`: managed rule group with no top-level action override (uses internal rule actions)
- For managed rule groups, individual rule overrides are in `managed.overrides`

### type
- `"managed_rule_group"`: ManagedRuleGroupStatement (includes all AWS managed + marketplace)
- `"custom"`: regular custom rule with any statement type
- `"rate_based"`: RateBasedStatement (may contain nested scope_down)

### statement.summary
Human-readable summary of the statement tree. Format:
- Leaf: `{field_type} {constraint} '{value}'` — e.g., `single_header:user-agent STARTS_WITH 'example'`
- JA4/JA3: `ja4_fingerprint EXACTLY 't13d...'`
- IP set: `ip_set '{set_name_or_arn}'`
- ASN: `asn_match [15169, 8075]`
- Geo: `geo_match [US, CN]`
- Label: `label_match 'awswaf:managed:...'`
- SQLi/XSS: `sqli_match(field)` / `xss_match(field)`
- Size: `size(body) > 8192`
- Regex: `regex_match(field, 'pattern')` or `regex_set(field, 'set_arn')`
- Logic: `AND(...)`, `OR(...)`, `NOT(...)`
- Rate-based scope_down: shown in `rate_based.scope_down.summary`

### statement.leaf_count
Total number of leaf-level match statements in the tree.

### statement.leaf_types
Deduplicated list of leaf statement types: `["byte_match", "asn_match", "label_match"]`

### statement.samples
Only populated when an OR branch has >3 same-type leaves (e.g., 30 JA4 fingerprints).
Contains first 2 + last 1 values:
```json
{
  "type": "ja4_fingerprint",
  "total": 30,
  "values": ["t12d240600_4f054e0fd0cf_...", "t12d320800_a6df2e0e78d0_...", "t13d5910h2_a33745022dd6_..."]
}
```
null when all branches have ≤3 leaves (no sampling needed).

### rule_labels
Array of label strings from the rule's RuleLabels field.
Empty array `[]` if no labels defined.
For managed rule groups, this is always `[]` — managed labels come from managed-labels.json.

### managed.config
Varies by managed rule group. Only populated for groups with ManagedRuleGroupConfigs.
- AntiDDoS AMR: `sensitivity_to_block`, `sensitivity_to_challenge`, `uris_exempt_from_challenge`
- Bot Control: `inspection_level` ("COMMON" | "TARGETED"), `enable_machine_learning` (bool)
- ATP: `login_path`, `request_inspection`, `response_inspection`
- ACFP: `creation_path`, `registration_page_path`, `request_inspection`, `response_inspection`
- Others: raw key-value pairs from ManagedRuleGroupConfigs

### scope_down
Present on managed rule groups and rate-based rules that have a scope-down statement.
null if no scope-down.
- `summary`: human-readable statement summary (same format as statement.summary)
- `source_lines`: line range in original JSON for fs_read fallback

### source
- `lines`: [start_line, end_line] in the original JSON file (1-indexed, inclusive)
- `jsonpath`: JSONPath expression to the rule object (for semantic context)
```

## Null/Missing Field Conventions

- Fields specific to a rule type are omitted (not null) when not applicable:
  - `managed` only present when type == "managed_rule_group"
  - `rate_based` only present when type == "rate_based"
- Optional fields that could apply to any type use null when absent:
  - `scope_down`: null if no scope-down
  - `challenge_config`: null if no rule-level override
  - `statement.samples`: null if no sampling needed
- Arrays use `[]` when empty, not null:
  - `rule_labels`: `[]`
  - `managed.overrides`: `[]`
  - `managed.excluded_rules`: `[]`
  - `token_domains`: `[]`
