#!/usr/bin/env python3
"""WAF Annotate Mermaid: Apply issue annotations to base Mermaid diagram.

Usage: python3 waf-annotate-mermaid.py <output_dir>
  output_dir: directory containing mermaid-base.md, mermaid-metadata.json,
              issue-rule-mapping.json, and waf-review-report.md

Reads issue-rule-mapping.json (written by LLM in Step 4):
  {"annotations": {"rule_name": "⚠️ Issue #1", ...}}

Outputs:
  {output_dir}/mermaid-final.md — annotated diagram
  Appends "## Appendix: Rule Execution Flow" to waf-review-report.md
"""
import json
import os
import re
import sys
from pathlib import Path


def _fatal(msg: str):
    print(msg, file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: FATAL")
    print(f"ACTION: FIX")
    print(f"CONTEXT: {msg}")
    sys.exit(2)


def _load_json(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        _fatal(f"Failed to read {path}: {e}")


def _build_rule_to_node(metadata: dict) -> dict[str, str]:
    """Map rule name → node_id from metadata."""
    mapping = {}
    for r in metadata.get("rules", []):
        mapping[r["name"]] = r["node_id"]
    return mapping


def _build_fold_lookup(metadata: dict) -> dict[str, dict]:
    """Map rule name → fold group info if the rule is folded."""
    lookup = {}
    for fg in metadata.get("fold_groups", []):
        for name in fg["rule_names"]:
            lookup[name] = fg
    return lookup


def _expand_fold_group(mermaid_lines: list, fold_group: dict,
                        metadata: dict) -> list[str]:
    """Replace a fold group node with individual rule nodes.
    Returns new lines with the group node replaced by expanded nodes."""
    gid = f"group_{fold_group['priorities'][0]}_{fold_group['priorities'][-1]}"
    new_lines = []
    for line in mermaid_lines:
        stripped = line.strip()
        if stripped.startswith(gid):
            # Replace group node with individual nodes
            for i, name in enumerate(fold_group["rule_names"]):
                priority = fold_group["priorities"][i]
                node_id = f"rule_{priority}"
                # Find rule info from metadata
                rule_meta = next((r for r in metadata["rules"]
                                  if r["name"] == name), None)
                if rule_meta:
                    new_lines.append(f'    {node_id}["{name}\\nP{priority}"]')
            continue
        # Update arrows referencing the group id
        if gid in stripped:
            # Replace group references with first/last rule of the group
            first_id = f"rule_{fold_group['priorities'][0]}"
            line = line.replace(gid, first_id)
        new_lines.append(line)

    # Add internal flow arrows between expanded nodes
    insert_lines = []
    for i in range(len(fold_group["priorities"]) - 1):
        curr = f"rule_{fold_group['priorities'][i]}"
        nxt = f"rule_{fold_group['priorities'][i + 1]}"
        insert_lines.append(f"    {curr} --> {nxt}")

    # Insert after the last expanded node
    last_priority = fold_group["priorities"][-1]
    last_id = f"rule_{last_priority}"
    result = []
    for line in new_lines:
        result.append(line)
        if line.strip().startswith(last_id) and "-->" not in line:
            result.extend(insert_lines)

    return result


def _annotate_node(line: str, node_id: str, annotation: str) -> str:
    """Add issue annotation to a node's label."""
    # Node line format: rule_0["P0: name\nAction: ..."]
    # Insert annotation before the closing bracket
    if node_id not in line or "-->" in line or "-.->" in line:
        return line

    # Find the closing bracket pattern and insert annotation before it
    # Handle both ["..."] and {{"..."}}
    for close_pattern in ('"]', '"}}'):
        if close_pattern in line:
            return line.replace(close_pattern,
                                f"\\n{annotation}{close_pattern}", 1)
    return line


def main():
    if len(sys.argv) < 2:
        _fatal("Usage: waf-annotate-mermaid.py <output_dir>")

    output_dir = sys.argv[1]

    # Load inputs
    base_path = os.path.join(output_dir, "mermaid-base.md")
    meta_path = os.path.join(output_dir, "mermaid-metadata.json")
    mapping_path = os.path.join(output_dir, "issue-rule-mapping.json")
    report_path = os.path.join(output_dir, "waf-review-report.md")

    for p in (base_path, meta_path, mapping_path, report_path):
        if not os.path.isfile(p):
            _fatal(f"Required file not found: {p}")

    base_text = Path(base_path).read_text(encoding="utf-8")
    metadata = _load_json(meta_path)
    mapping = _load_json(mapping_path)
    annotations = mapping.get("annotations", {})

    if not annotations:
        # No annotations — just copy base to final and append
        Path(os.path.join(output_dir, "mermaid-final.md")).write_text(
            base_text, encoding="utf-8")
        _append_to_report(report_path, base_text)
        print("No annotations to apply", file=sys.stderr)
        _print_result(0)
        return

    rule_to_node = _build_rule_to_node(metadata)
    fold_lookup = _build_fold_lookup(metadata)

    # Strip mermaid code fence for processing
    mermaid_content = base_text
    mermaid_content = re.sub(r'^```mermaid\s*\n', '', mermaid_content)
    mermaid_content = re.sub(r'\n```\s*$', '', mermaid_content)
    lines = mermaid_content.split("\n")

    # Phase 1: Expand fold groups that contain annotated rules
    expanded_groups = set()
    for rule_name in annotations:
        if rule_name in fold_lookup:
            fg = fold_lookup[rule_name]
            fg_key = f"{fg['priorities'][0]}_{fg['priorities'][-1]}"
            if fg_key not in expanded_groups:
                lines = _expand_fold_group(lines, fg, metadata)
                expanded_groups.add(fg_key)

    # Phase 2: Apply annotations to node lines
    applied = 0
    for rule_name, annotation in annotations.items():
        node_id = rule_to_node.get(rule_name)
        if not node_id:
            continue
        new_lines = []
        for line in lines:
            new_line = _annotate_node(line, node_id, annotation)
            if new_line != line:
                applied += 1
            new_lines.append(new_line)
        lines = new_lines

    # Reassemble
    final_mermaid = "```mermaid\n" + "\n".join(lines) + "\n```\n"
    final_path = os.path.join(output_dir, "mermaid-final.md")
    Path(final_path).write_text(final_mermaid, encoding="utf-8")

    # Append to report
    _append_to_report(report_path, final_mermaid)

    print(f"Applied {applied} annotations, expanded {len(expanded_groups)} fold groups",
          file=sys.stderr)
    _print_result(applied)


def _append_to_report(report_path: str, mermaid_text: str):
    """Append Mermaid diagram as appendix to the report."""
    appendix = f"\n---\n\n## Appendix: Rule Execution Flow\n\n{mermaid_text}"
    with open(report_path, "a", encoding="utf-8") as f:
        f.write(appendix)


def _print_result(applied: int):
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"ANNOTATIONS_APPLIED: {applied}")


if __name__ == "__main__":
    main()
