#!/usr/bin/env python3
"""WAF Render HTML: Convert waf-review-report.md into a self-contained HTML file.

Usage: python3 waf-render-html.py <output_dir>
  output_dir: directory containing waf-review-report.md and work/

Outputs: {output_dir}/waf-review-report.html

Supports the Markdown the report uses: headings, paragraphs, nested lists,
tables, fenced code, blockquotes, horizontal rules, bold, italic, inline code,
and links. The Mermaid block is replaced with a rule flow drawn in HTML/CSS
from work/, so the file needs no JavaScript and works offline.

After writing, every word of the Markdown (outside the Mermaid block) is
checked against the HTML text. Missing words make the run FATAL.
"""
import html
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from waf_utils import fatal, work_path

TEXT = {
    "en": {"flow": "Rule Execution Flow", "request": "Request", "no_match": "no match",
           "token": "valid token / no match", "allowed": "✅ Allowed", "blocked": "🚫 Blocked",
           "non_browser": "non-browser → Blocked", "default": "Default action",
           "scope": "Scope-down", "overrides": "Overrides", "labels": "Adds labels",
           "uses": "Uses label", "from": "from", "issues": "Issues"},
    "zh": {"flow": "规则执行流程", "request": "请求", "no_match": "未匹配",
           "token": "token 有效 / 未匹配", "allowed": "✅ 放行", "blocked": "🚫 拦截",
           "non_browser": "非浏览器 → 等于拦截", "default": "默认动作",
           "scope": "Scope-down", "overrides": "Override", "labels": "添加标签",
           "uses": "使用标签", "from": "来自", "issues": "相关问题"},
}

ACTION_NAMES = {"managed_default": "Managed", "allow": "Allow", "block": "Block", "count": "Count",
                "challenge": "Challenge", "captcha": "CAPTCHA"}

CSS = """
:root{--fg:#1f2328;--mut:#59636e;--line:#d1d9e0;--soft:#f6f8fa;--link:#0969da;
--crit:#cf222e;--med:#bf8700;--low:#1a7f37;--aw:#0969da}
*{box-sizing:border-box}
body{margin:0;color:var(--fg);background:#fff;font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
main{max-width:980px;margin:0 auto;padding:40px 24px 80px}
h1{font-size:28px;margin:0 0 16px}
h2{font-size:20px;margin:36px 0 12px;padding-top:8px}
h3{font-size:17px;margin:28px 0 10px}
h2[id^=issue-]{border-left:5px solid var(--line);padding-left:12px}
h2.sev-critical{border-color:var(--crit)}h2.sev-medium{border-color:var(--med)}
h2.sev-low{border-color:var(--low)}h2.sev-awareness{border-color:var(--aw)}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
code{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--soft);padding:1px 5px;border-radius:4px;word-break:break-word}
pre{background:var(--soft);border:1px solid var(--line);border-radius:6px;padding:12px 14px;overflow:auto}
pre code{background:none;padding:0;word-break:normal}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:14px}
th,td{border:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}
th{background:var(--soft)}
hr{border:0;border-top:1px solid var(--line);margin:28px 0}
blockquote{margin:12px 0;padding:4px 14px;border-left:4px solid var(--line);color:var(--mut)}
ul,ol{padding-left:24px}li{margin:3px 0}
.flow{margin:16px 0}
.fnode{border:1px solid var(--line);border-radius:8px;padding:10px 14px;background:#fff;position:relative}
.fnode.start,.fnode.end{display:inline-block;background:var(--soft);font-weight:600}
.frow{display:flex;gap:12px;align-items:stretch}
.frow .fnode{flex:1;min-width:0}
.fexit{flex:0 0 150px;align-self:center;font-size:13px;color:var(--mut);text-align:center}
.fexit b{display:block;color:var(--fg);font-size:14px}
.farrow{padding:2px 0 2px 28px;color:var(--mut);font-size:12px}
.farrow::before{content:"↓ "}
.fhead{font-weight:600;word-break:break-word}
.fprio{display:inline-block;min-width:38px;color:var(--mut)}
.fact{display:inline-block;font-size:12px;border:1px solid var(--line);border-radius:10px;padding:0 8px;margin-left:6px;font-weight:500}
.act-allow{border-left:4px solid var(--low)}.act-block{border-left:4px solid var(--crit)}
.act-challenge,.act-captcha{border-left:4px solid var(--med)}
.fdet{font-size:13px;color:var(--mut);margin-top:4px;word-break:break-word}
.fdet div{margin-top:2px}
.fiss{margin-top:6px;font-size:13px}
.fiss a{display:inline-block;background:#fff8c5;border:1px solid #d4a72c;border-radius:10px;padding:0 7px;margin:2px 4px 0 0;color:#6e5600}
@media print{main{max-width:none;padding:0}a{color:inherit}.fnode,pre,table,h2{break-inside:avoid}}
"""


# ── Inline Markdown ────────────────────────────────────────────────────────

def _inline(text: str, issues: set) -> str:
    """Render inline Markdown. Code spans and backslash escapes become
    placeholders first, so nothing inside them is interpreted and bold or
    italic can still span across them."""
    held = []

    def hold(frag: str) -> str:
        held.append(frag)
        return f"\x00{len(held) - 1}\x00"

    def code(m):
        c = m.group(2)
        if len(c) > 2 and c[0] == c[-1] == " ":  # CommonMark strips one space each side
            c = c[1:-1]
        return hold(f"<code>{html.escape(c)}</code>")
    text = re.sub(r"(`+)(.+?)\1", code, text)
    text = re.sub(r"\\([\\`*_{}\[\]()#+\-.!|>~])", lambda m: hold(html.escape(m.group(1))), text)
    s = html.escape(text, quote=False)
    s = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)",
               lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>', s)  # already escaped
    s = re.sub(r"\*\*(?=\S)(.+?)(?<=\S)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<![\w*])\*(?=[^\s*])(.+?)(?<=[^\s*])\*(?![\w*])", r"<em>\1</em>", s)
    s = re.sub(r"(?<!\w)_(?=[^\s_])(.+?)(?<=[^\s_])_(?!\w)", r"<em>\1</em>", s)
    s = re.sub(r"&lt;br\s*/?&gt;", "<br>", s)  # the only inline HTML reports use
    s = re.sub(r"(?<![\w&#/])#(\d+)\b",
               lambda m: f'<a href="#issue-{m.group(1)}">#{m.group(1)}</a>'
               if m.group(1) in issues else m.group(0), s)
    return re.sub(r"\x00(\d+)\x00", lambda m: held[int(m.group(1))], s)


# ── Block Markdown ─────────────────────────────────────────────────────────

LIST_RE = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$")


def _split_row(line: str) -> list:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|") and not line.endswith("\\|"):
        line = line[:-1]
    cells, cur, i = [], "", 0
    while i < len(line):
        if line[i] == "\\" and i + 1 < len(line) and line[i + 1] == "|":
            cur += "\\|"
            i += 2
            continue
        if line[i] == "|":
            cells.append(cur.strip())
            cur = ""
        else:
            cur += line[i]
        i += 1
    cells.append(cur.strip())
    return cells


def _render_list(items: list, issues: set) -> str:
    """items: (indent, marker, text) tuples. Nest by indent."""
    out, stack = [], []  # stack of (indent, tag)
    for indent, marker, text in items:
        ordered = marker[0].isdigit()
        tag = "ol" if ordered else "ul"
        start = int(marker[:-1]) if ordered else 1
        open_tag = f'<ol start="{start}">' if ordered and start != 1 else f"<{tag}>"
        while stack and indent < stack[-1][0]:
            out.append(f"</li></{stack.pop()[1]}>")
        if stack and indent == stack[-1][0]:
            out.append("</li>")
            if stack[-1][1] != tag:
                out.append(f"</{stack.pop()[1]}>{open_tag}")
                stack.append((indent, tag))
        else:
            out.append(open_tag)
            stack.append((indent, tag))
        out.append(f"<li>{_inline(text, issues)}")
    while stack:
        out.append(f"</li></{stack.pop()[1]}>")
    return "".join(out)


def _render_blocks(lines: list, issues: set, flow_html: str) -> tuple[str, list]:
    """Return (html, lines excluded from the content check)."""
    out, skipped, i = [], [], 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            i += 1
            continue
        # Fenced code
        m = re.match(r"^(\s*)(`{3,}|~{3,})\s*([\w-]*)", line)
        if m:
            fence, lang = m.group(2), m.group(3)
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith(fence):
                j += 1
            body = lines[i + 1:j]
            if lang == "mermaid" and flow_html:
                out.append(flow_html)
                skipped += body
            else:
                cls = f' class="language-{lang}"' if lang else ""
                out.append(f"<pre><code{cls}>{html.escape(chr(10).join(body))}</code></pre>")
            i = j + 1
            continue
        # HTML comment (appendix markers)
        if stripped.startswith("<!--"):
            while i < len(lines) and "-->" not in lines[i]:
                i += 1
            i += 1
            continue
        # Heading
        m = re.match(r"^(#{1,6})\s+(.*?)(?:\s+#+)?$", stripped)
        if m:
            level, text = len(m.group(1)), m.group(2)
            attrs = ""
            im = re.match(r"(?:Issue|问题)\s+#?(\d+)\s*\(([^)]+)\)", text)
            if level == 2 and im:
                sev = re.sub(r"[^a-z]", "", im.group(2).lower())
                attrs = f' id="issue-{im.group(1)}" class="sev-{sev}"'
            out.append(f"<h{level}{attrs}>{_inline(text, issues)}</h{level}>")
            i += 1
            continue
        # Horizontal rule
        if re.match(r"^(-{3,}|\*{3,}|_{3,})$", stripped):
            out.append("<hr>")
            i += 1
            continue
        # Table
        if (stripped.startswith("|") and i + 1 < len(lines)
                and re.match(r"^\s*\|?\s*:?-{2,}", lines[i + 1])):
            head = _split_row(lines[i])
            rows = []
            j = i + 2
            while j < len(lines) and lines[j].strip().startswith("|"):
                rows.append(_split_row(lines[j]))
                j += 1
            th = "".join(f"<th>{_inline(c, issues)}</th>" for c in head)
            trs = "".join("<tr>" + "".join(f"<td>{_inline(c, issues)}</td>" for c in r) + "</tr>"
                          for r in rows)
            out.append(f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>")
            i = j
            continue
        # Blockquote
        if stripped.startswith(">"):
            quote = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(re.sub(r"^\s*>\s?", "", lines[i]))
                i += 1
            inner, sk = _render_blocks(quote, issues, flow_html)
            out.append(f"<blockquote>{inner}</blockquote>")
            skipped += sk
            continue
        # List (continuation lines join the previous item)
        if LIST_RE.match(line):
            items = []
            while i < len(lines):
                lm = LIST_RE.match(lines[i])
                if lm:
                    items.append((len(lm.group(1).expandtabs(4)), lm.group(2), lm.group(3)))
                elif (lines[i].strip() and not _starts_block(lines, i) and items
                      and not re.match(r"\s*(`{3,}|~{3,})", lines[i])):
                    ind, o, t = items[-1]  # continuation line keeps its line break
                    items[-1] = (ind, o, t + "<br>" + lines[i].strip())
                elif not lines[i].strip():
                    # A blank line between items keeps them in one list
                    j = i
                    while j < len(lines) and not lines[j].strip():
                        j += 1
                    if j < len(lines) and LIST_RE.match(lines[j]):
                        i = j
                        continue
                    break
                else:
                    break
                i += 1
            out.append(_render_list(items, issues))
            continue
        # Paragraph: each source line keeps its own line, as the report intends
        para = []
        while i < len(lines) and lines[i].strip() and not _starts_block(lines, i):
            para.append(lines[i].strip())
            i += 1
        out.append("<p>" + "<br>".join(_inline(p, issues) for p in para) + "</p>")
    return "\n".join(out), skipped


def _starts_block(lines: list, i: int) -> bool:
    s = lines[i].strip()
    return bool(re.match(r"^(#{1,6}\s|`{3,}|~{3,}|>|<!--|(-{3,}|\*{3,}|_{3,})$)", s)
                or LIST_RE.match(lines[i])
                or (s.startswith("|") and i + 1 < len(lines)
                    and re.match(r"^\s*\|?\s*:?-{2,}", lines[i + 1])))


# ── Rule flow ──────────────────────────────────────────────────────────────

def _flow(summary: dict, annotations: dict, deps: list, issues: set, T: dict) -> str:
    rules = sorted(summary.get("rules", []), key=lambda r: r["priority"])
    if not rules:
        return ""
    by_name = {r["name"]: r for r in rules}
    e = html.escape
    parts = [f'<section class="flow" data-flow><div class="fnode start">{T["request"]}</div>']
    for r in rules:
        act = r["action"]
        det = []
        mg = r.get("managed")
        if mg:
            det.append(e(f"{mg.get('vendor', 'AWS')}/{mg.get('group_name', '')} {mg.get('version') or ''}".strip()))
            if mg.get("overrides"):
                det.append(f'{T["overrides"]}: ' + e(", ".join(
                    f"{o['rule_name']}→{ACTION_NAMES.get(o['action'], o['action'])}" for o in mg["overrides"])))
        else:
            det.append(f'<code>{e(r.get("statement", {}).get("summary", ""))}</code>')
        if r.get("scope_down"):
            det.append(f'{T["scope"]}: <code>{e(r["scope_down"]["summary"])}</code>')
        if r.get("rule_labels"):
            det.append(f'{T["labels"]}: ' + ", ".join(f"<code>{e(l)}</code>" for l in r["rule_labels"]))
        for d in deps:
            if d["consumer"] == r["name"] and d["producer"] in by_name:
                p = by_name[d["producer"]]
                det.append(f'{T["uses"]} <code>{e(d["label"])}</code> {T["from"]} '
                           f'<a href="#rule-{p["priority"]}">P{p["priority"]}</a>')
        nums = re.findall(r"#(\d+)", annotations.get(r["name"], ""))
        iss = "".join(f'<a href="#issue-{n}">#{n}</a>' for n in nums if n in issues)
        node = (f'<div class="fnode act-{e(act)}" id="rule-{r["priority"]}">'
                f'<div class="fhead"><span class="fprio">P{r["priority"]}</span>{e(r["name"])}'
                f'<span class="fact">{ACTION_NAMES.get(act, e(act))}</span></div>'
                f'<div class="fdet">' + "".join(f"<div>{x}</div>" for x in det) + "</div>"
                + (f'<div class="fiss">{T["issues"]}: {iss}</div>' if iss else "") + "</div>")
        exit_ = {"allow": T["allowed"], "block": T["blocked"]}.get(act)
        if act in ("challenge", "captcha"):
            exit_ = T["non_browser"]
        parts.append(f'<div class="frow">{node}'
                     + (f'<div class="fexit">→ <b>{exit_}</b></div>' if exit_ else "") + "</div>")
        parts.append(f'<div class="farrow">'
                     f'{T["token"] if act in ("challenge", "captcha") else T["no_match"] if act in ("allow", "block") else ""}</div>')
    da = summary.get("web_acl", {}).get("default_action", "")
    parts.append(f'<div class="fnode end">{T["default"]}: {e(da)} '
                 f'{T["allowed"] if da == "allow" else T["blocked"]}</div></section>')
    return "\n".join(parts)


# ── Content check ──────────────────────────────────────────────────────────

def _words(text: str) -> Counter:
    # Outer underscores may be emphasis markers, not part of the word
    return Counter(w.strip("_") for w in re.findall(r"\w+", text) if w.strip("_"))


def _check(md_lines: list, skipped: list, page: str) -> list:
    """Words in the Markdown that don't appear in the HTML text."""
    skip = Counter(skipped)
    kept = []
    for l in md_lines:
        if skip[l]:
            skip[l] -= 1
            continue
        kept.append(l)
    md_text = re.sub(r"<!--.*?-->", " ", "\n".join(kept), flags=re.S)
    md_text = re.sub(r"\[([^\]]+)\]\([^)\s]+\)", r"\1", md_text)  # link URLs aren't text
    md_text = re.sub(r"<br\s*/?>", " ", md_text)
    md_text = re.sub(r"^\s*\d+[.)]\s+", " ", md_text, flags=re.M)  # <ol> draws the numbers
    md_text = re.sub(r"^\s*(`{3,}|~{3,})[\w-]*", " ", md_text, flags=re.M)  # fence info strings
    body = re.sub(r"<section class=\"flow\" data-flow>.*?</section>", " ", page, flags=re.S)
    body = re.sub(r"<style>.*?</style>|<title>.*?</title>", " ", body, flags=re.S)
    body_text = html.unescape(re.sub(r"<[^>]+>", " ", body))
    missing = _words(md_text) - _words(body_text)
    return sorted(missing)


def main():
    if len(sys.argv) < 2:
        fatal("Usage: waf-render-html.py <output_dir>")
    output_dir = sys.argv[1]
    report_path = os.path.join(output_dir, "waf-review-report.md")
    if not os.path.isfile(report_path):
        fatal(f"waf-review-report.md not found in {output_dir}")

    def load(name):
        p = work_path(output_dir, name)
        return json.loads(Path(p).read_text(encoding="utf-8")) if os.path.isfile(p) else {}

    md = Path(report_path).read_text(encoding="utf-8")
    summary = load("waf-summary.json")
    lang = load("findings-metadata.json").get("lang", "en")
    T = TEXT["zh" if lang == "zh" else "en"]
    issues = set(re.findall(r"^##\s+(?:Issue|问题)\s+#?(\d+)", md, re.M))
    flow_html = _flow(summary, load("issue-rule-mapping.json").get("annotations", {}),
                      load("mermaid-metadata.json").get("label_dependencies", []), issues, T)

    lines = md.splitlines()
    body, skipped = _render_blocks(lines, issues, flow_html)
    title = next((re.sub(r"^#\s+", "", l) for l in lines if l.startswith("# ")), "WAF Review")
    acl = summary.get("web_acl", {}).get("name", "")
    page = (f'<!DOCTYPE html>\n<html lang="{"zh-CN" if lang == "zh" else "en"}">\n<head>\n'
            f'<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{html.escape(title + (' · ' + acl if acl else ''))}</title>\n<style>{CSS}</style>\n"
            f"</head>\n<body>\n<main>\n{body}\n</main>\n</body>\n</html>\n")

    output_file = os.path.join(output_dir, "waf-review-report.html")
    try:
        Path(output_file).write_text(page, encoding="utf-8")
    except OSError as e:
        fatal(f"Failed to write {output_file}: {e}")

    missing = _check(lines, skipped, page)
    if missing:
        fatal(f"HTML written to {output_file}, but {len(missing)} words from the Markdown are "
              f"missing from it: {', '.join(missing[:20])}. Report the Markdown file instead.")
    rule_ids = set(re.findall(r'id="rule-(\d+)"', page))
    lost = [r["name"] for r in summary.get("rules", []) if str(r["priority"]) not in rule_ids]
    if flow_html and lost:
        fatal(f"Rule flow is missing rules: {', '.join(lost)}")

    print(f"Rendered {len(issues)} issues and {len(rule_ids)} rules", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"OUTPUT_FILE: {output_file}")
    print(f"ISSUES: {len(issues)}")
    print(f"FLOW_RULES: {len(rule_ids)}")


if __name__ == "__main__":
    main()
