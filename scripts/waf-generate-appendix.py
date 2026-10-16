#!/usr/bin/env python3
"""Generate fixed appendix content for WAF review reports.

The LLM decides which sections to reference. Dynamic parts: WCU capacity from
waf-summary.json, Appendix B/C (Anti-DDoS patterns) only for Web ACLs that
have Anti-DDoS AMR or face the internet with a default Allow, and Appendix I
(sensitive-file probes) only for a default Allow. Letters stay fixed so
references don't shift.
"""

import json
import os
import re
import sys
from pathlib import Path
from waf_utils import fatal, work_path

APPENDIX_SECTIONS = r"""
---

# Appendix

## Appendix A: ASN + UA Crawler Labeling Rule

Place this rule **before** AntiDDoS AMR and Always-on Challenge. It labels verified search engine crawlers so downstream rules can exclude them via scope-down. The JSON shows `SearchString` as plain text; the API and CLI take it as base64.

```json
{{
  "Name": "label-verified-crawlers",
  "Priority": "<place before AntiDDoS AMR>",
  "Action": {{
    "Count": {{}}
  }},
  "RuleLabels": [
    {{ "Name": "crawler:verified" }}
  ],
  "VisibilityConfig": {{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "label-verified-crawlers"
  }},
  "Statement": {{
    "OrStatement": {{
      "Statements": [
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "ByteMatchStatement": {{
                  "SearchString": "googlebot",
                  "FieldToMatch": {{ "SingleHeader": {{ "Name": "user-agent" }} }},
                  "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}],
                  "PositionalConstraint": "CONTAINS"
                }}
              }},
              {{ "AsnMatchStatement": {{ "AsnList": [15169] }} }}
            ]
          }}
        }},
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "ByteMatchStatement": {{
                  "SearchString": "bingbot",
                  "FieldToMatch": {{ "SingleHeader": {{ "Name": "user-agent" }} }},
                  "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}],
                  "PositionalConstraint": "CONTAINS"
                }}
              }},
              {{ "AsnMatchStatement": {{ "AsnList": [8075] }} }}
            ]
          }}
        }},
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "ByteMatchStatement": {{
                  "SearchString": "yandexbot",
                  "FieldToMatch": {{ "SingleHeader": {{ "Name": "user-agent" }} }},
                  "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}],
                  "PositionalConstraint": "CONTAINS"
                }}
              }},
              {{ "AsnMatchStatement": {{ "AsnList": [13238, 208722] }} }}
            ]
          }}
        }}
      ]
    }}
  }}
}}
```

Confirmed ASNs: Google 15169, Bing 8075, Yandex 13238 + 208722. For other search engines (Baidu, Yahoo Japan, etc.), verify current ASNs from their official documentation before adding.

---

## Appendix B: Dual AntiDDoS AMR Instance Pattern

When browser traffic and API or native app traffic share one host and need different AntiDDoS strategies. If the API traffic has its own host, one instance is enough: exempt that host from Challenge in the exempt regex (`^api\.example\.com\/`), which AWS WAF matches against the host followed by the normalized path. If that host also has its own distribution or load balancer, a separate Web ACL for it is simpler still.

1. **Add a Count+Label rule before both AMR instances** that labels browser requests: `GET` with `Accept` containing `text/html`, label `custom:browser-request`. This rule must have a higher priority (lower number) than both AMR instances.
2. **AMR instance 1 (browser traffic)**: scope-down matches the browser label and excludes the crawler label. `ChallengeAllDuringEvent` enabled. Block sensitivity: LOW (default).
3. **AMR instance 2 (API and native app traffic)**: scope-down excludes the browser label. `ChallengeAllDuringEvent` overridden to Count. Block sensitivity: MEDIUM (since Challenge is unavailable, raise Block sensitivity for adequate protection).
4. **Implementation**: The AWS console does not allow adding the same managed rule group twice. First copy the existing AMR rule's JSON. Then create a new **custom rule** in the Web ACL, open its **JSON editor**, paste the copied AMR JSON, change `Name` and `MetricName` to unique values (e.g., `AntiDDoS-API`), then save.

The cost: flood requests that don't look like a browser page load, such as `Accept: */*`, land in instance 2 and get Block only, not Challenge. That's still far better than turning `ChallengeAllDuringEvent` off for everything.

Crawler exclusion scope-down (add to AMR scope-down via `AndStatement` if AMR already has one):

```json
{{
  "NotStatement": {{
    "Statement": {{
      "LabelMatchStatement": {{
        "Scope": "LABEL",
        "Key": "crawler:verified"
      }}
    }}
  }}
}}
```

---

## Appendix C: Always-on Challenge for Landing Pages

Two-rule pattern for proactive DDoS defense on landing page URIs:

1. **Label rule** (Count+Label): matches landing page URIs (e.g., `/`, `/login`, `/signup`) and adds label `custom:landing-page`. Action: Count (request continues).
2. **Challenge rule**: matches `custom:landing-page` label and applies Challenge action. Exclude verified crawlers by adding a `NotStatement` for `crawler:verified` label.

The user must define their own landing page URI list based on their application.

Recommended token immunity time: ≥ 4 hours (14400 seconds). Real users complete JS verification once and browse uninterrupted for the entire immunity period.

---

## Appendix D: Recommended Rule Priority Order

| Position | Rule Type | Rationale |
|----------|-----------|-----------|
| 1 | IP whitelist (Allow, IP sets only) | Trusted IPs bypass all rules |
| 2 | IP blacklist (Block) | Known malicious IPs blocked immediately |
| 3 | Count+Label rules | Tag traffic types for downstream scope-down |
| 4 | AntiDDoS AMR | Needs full traffic for accurate baseline |
| 5 | IP reputation rule group | Low WCU, filters known malicious IPs |
| 6 | Anonymous IP rule group | Filters anonymous/hosting provider IPs |
| 7 | Rate-based rules | Rate limiting before Challenge |
| 8 | Always-on Challenge | Proactive DDoS defense for landing pages |
| 9 | Custom rules | Business-specific logic |
| 10 | Application layer rule groups (CRS, KnownBadInputs) | OWASP Top 10 protections |
| 11 | Bot Control / ATP / ACFP | Per-request pricing, place last |

Key principles: label producers before consumers, AntiDDoS AMR as early as possible, cheaper rules before expensive ones. Excluding verified crawlers from AntiDDoS AMR (Appendix A) is the one scope-down it should get outside the two-instance pattern (Appendix B).

This order is for a Web ACL that allows by default. When the default action is Block, the Allow rules are the way in: put content inspection groups (position 10) ahead of them, or they only see traffic that is blocked anyway.

---

## Appendix E: WCU Capacity Reminder

{wcu_text}

After implementing any recommended changes, verify the new WCU total does not exceed 5000, a fixed maximum. The base Web ACL price covers 1,500 WCU; each 500 WCU beyond that adds a per-request charge (see the AWS WAF pricing page), and Shield Advanced covers standard AWS WAF fees only up to 1,500 WCU. Check in the AWS Console: WAF → Web ACLs → select your Web ACL → the capacity is shown in the overview.

---

## Appendix F: Common Override Recommendations

When adding or reviewing managed rule groups, consider these common overrides:

**AWSManagedRulesCommonRuleSet (CRS):**
- Override `SizeRestrictions_BODY` to **Count**. This rule blocks request bodies larger than 8KB, which frequently causes false positives on file upload endpoints, API endpoints with large payloads, and form submissions with rich content.

**AWSManagedRulesBotControlRuleSet (Bot Control Common level):**
- `SignalNonBrowserUserAgent` and `CategoryHttpLibrary` block non-browser User-Agents by default. If native apps (okhttp, gohttp), API clients, partners, or monitoring reach this Web ACL, override both to **Count**, or scope Bot Control so that traffic doesn't enter it.
- For a site only browsers use, keep both at the default Block.

**AWSManagedRulesAnonymousIpList:**
- Review `HostingProviderIPList` carefully. Default Block will block requests from cloud platforms and hosting providers. If your clients may originate from cloud-hosted environments (e.g., enterprise users behind cloud proxies, SaaS integrations), override to **Count**. Never override to Allow: that lets cloud-hosted attack traffic bypass all subsequent rules.

---

## Appendix G: Encoding and Decoding in Custom Rules

A custom rule should match the string the origin acts on. If the origin decodes `/%69nternal/` to `/internal/` and serves it, a rule that inspects the path has to decode too, or it never sees `/internal/`.

**Mistakes in the two directions don't cost the same.** A rule that decodes less than the origin fails open. A Block rule misses encoded variants such as `/%69nternal/` or `%2569`, and an Allow rule or exemption without normalization also matches `/public/../admin`. Nothing in the logs shows it. A rule that decodes more than the origin fails closed. A Block rule can match a request the origin treats as plain data, such as `%2F` inside a path segment, and an Allow rule matches less. Those are false positives, and they show up while the rule runs in Count. That's why the reference chains below lean toward decoding more.

**Why AWS WAF doesn't decode by default.** Without a text transformation, WAF inspects the URI path "exactly as it receives it from the client", and the body as plain text. WAF can't know how an origin decodes a request. Frameworks don't even agree on where a query parameter ends: API Gateway REST APIs also split on `;`. And some rules need the raw bytes, such as the one in Appendix H. So the author of each rule picks its transformations, with the goal AWS describes: inspect "requests the same way your application interprets them".

**CloudFront** normalizes the path only to choose a cache behavior, and sends the raw path to the origin. `..`, `//`, and encoded characters reach the origin as the client sent them, unless a CloudFront Function or Lambda@Edge rewrites the path. Write rules as if the path WAF inspects isn't normalized either.

**Managed rule groups** pick their own transformations, and you can't change them. Everything here is about custom rules.

**Reference chains.** Transformations run in priority order, lowest first. Each costs 10 WCU, and a statement takes at most 10 transformations. Put several values in one regex or regex pattern set so they share a chain.

| Field | Reference chain | Notes |
|---|---|---|
| `UriPath` | `URL_DECODE`, `URL_DECODE`, `REMOVE_NULLS`, `NORMALIZE_PATH`, `LOWERCASE` | |
| `QueryString`, `SingleQueryArgument`, `AllQueryArguments` | `URL_DECODE`, `URL_DECODE`, `REMOVE_NULLS`, `LOWERCASE` | No `NORMALIZE_PATH`: it would rewrite `//` and `../` inside values. The argument fields split the raw query string, so `%26` and `%3D` don't separate arguments. A `URL_DECODE` in `PreParseTextTransformations` changes that, and `REPLACE_SEMICOLONS_WITH_AMPERSANDS` (a pre-parse type only) splits on `;` the way API Gateway REST APIs do. Pre-parse transformations apply to `SingleQueryArgument` and `AllQueryArguments` only |
| `Body` with a form | `URL_DECODE`, `URL_DECODE`, `REMOVE_NULLS`, `LOWERCASE` | Form bodies are URL-encoded like a query string |
| `JsonBody` | `JS_DECODE` if the application unescapes JSON strings | `JS_DECODE` decodes JavaScript escapes such as `\u0069` |
| Headers, cookies | For attack payloads, the query string chain if the application URL-decodes the value; otherwise `LOWERCASE` where case doesn't matter | Many frameworks URL-decode cookie values; few decode headers. A rule on a value the client picks, such as the User-Agent, only stops clients that don't change it, so decoding adds nothing there |

**Variants.** Pick by what the origin does. Each one has a cost.
- One `URL_DECODE` or two: the second one covers double encoding such as `%2569`, in case the origin or a proxy in front of it decodes twice. It costs 10 WCU, and a literal `%41` a user typed (sent as `%2541`) becomes `A`.
- `URL_DECODE_UNI` instead of `URL_DECODE`: it also decodes IIS-style `%uXXXX`, which matters in front of IIS. The cost: the deprecated JavaScript `escape()` sends non-ASCII text as `%uXXXX`, and outside the full-width range only the low byte is kept. Non-Latin text turns into arbitrary ASCII that can match a pattern by chance.
- `NORMALIZE_PATH_WIN` instead of `NORMALIZE_PATH`: it also turns `\` into `/`, which matters when the origin treats `\` as a path separator (Windows, IIS). The cost: a legitimate `\` in the path is rewritten too. Use it on paths only.

**Order.** Decode first, then clean up. With `LOWERCASE` before a decode, `%49nternal` becomes `Internal` after decoding. With `NORMALIZE_PATH` before a decode, `/%2e%2e/` isn't collapsed. With `REMOVE_NULLS` before a decode, the null byte from `%00` survives.

**A leading `../`.** `NORMALIZE_PATH` keeps a `../` at the very start, so `/../admin` passes the whole chain unchanged, while most origins resolve it to `/admin`. Core rule set's `GenericLFI_URIPATH`, in Block, looks for path traversal such as `../` (Appendix I lists `/foo/../.env` among the paths it blocks).

**Path parameters.** Java servlet containers such as Tomcat drop `;` path parameters before routing, so `/admin;x=1` reaches `/admin`. No text transformation removes them. A rule that matches `/admin` with `EXACTLY`, `ENDS_WITH`, or a regex anchored with `$` or `(/|$)` misses that request. In front of such an origin, end the match with `(/|;|$)`, or block `;` on paths that never use it. Tomcat also reads `..;` as `..`, so `/public/..;/admin` can get past a prefix Allow or exemption that `NORMALIZE_PATH` would otherwise protect.

**Rules that let requests through** need normalizing too. An Allow rule or NOT condition with `STARTS_WITH /public/` and no `NORMALIZE_PATH` also matches `/public/../admin`. With `NORMALIZE_PATH` but no decode before it, `/public/%2e%2e/admin` still starts with `/public/`. These conditions need the decode first, then the normalization.

**Rules that must not decode.** A rule that looks for the encoding itself, such as `%00` or the encoded letters in Appendix H, loses what it looks for once it decodes. The review doesn't flag conditions whose pattern spells out `%XX`.

Run every change in Count before switching it to Block.

---

## Appendix H: Block Encoded Unreserved Characters and Null Bytes

RFC 3986 section 2.3 says URI producers shouldn't percent-encode letters, digits, `-`, `.`, `_`, and `~`. Browsers and common HTTP libraries follow it. So `%69` for `i` or `%2e` for `.` usually comes from a scanner trying to get past a rule, as in `/%69nternal/` or `%2e%2e/`. This rule catches encoded letters, digits, and dots on every path and in the query string, whatever transformations the other rules use. It doesn't cover `//` or `/./`, case changes, or IIS-style `%u0069`.

Don't block `%` itself. Legitimate requests encode spaces (`%20`), non-ASCII text (`%E4%B8%AD`), and reserved characters used as data (`%26`, `%3D`, `%2F`, `%3A`, `%40`), as in `url=https%3A%2F%2F...`.

```json
{{
  "Name": "block-encoded-unreserved",
  "Priority": "<place early, ahead of any Allow rule that matches on the path>",
  "Action": {{ "Block": {{}} }},
  "VisibilityConfig": {{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "block-encoded-unreserved"
  }},
  "Statement": {{
    "OrStatement": {{
      "Statements": [
        {{
          "RegexMatchStatement": {{
            "RegexString": "%(25)?(3[0-9]|[46][1-9a-f]|[57][0-9a]|2[de]|5f|00)",
            "FieldToMatch": {{ "UriPath": {{}} }},
            "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}]
          }}
        }},
        {{
          "RegexMatchStatement": {{
            "RegexString": "%(25)?(3[0-9]|[46][1-9a-f]|[57][0-9a]|2[de]|5f|00)",
            "FieldToMatch": {{ "QueryString": {{}} }},
            "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}]
          }}
        }}
      ]
    }}
  }}
}}
```

- The only transformation is `LOWERCASE`, so `%4A` and `%4a` both match. Don't add `URL_DECODE`: the rule inspects the encoding itself.
- What the regex matches: `3[0-9]` is the digits; `4[1-9a-f]` and `5[0-9a]` are `A` to `Z`; `6[1-9a-f]` and `7[0-9a]` are `a` to `z`; `2[de]` and `5f` are `-`, `.`, and `_`; `00` is the null byte, which has no legitimate use in a URL. The optional `25` catches the same characters encoded twice, such as `%2569`.
- `~` (`%7E`) is left out on purpose. Java's `URLEncoder` encodes it, and so did Python before 3.7.
- The optional `25` also matches a literal `%` a user typed, when the two characters after it spell one of these codes: a search for `50%30` is sent as `50%2530` and matches, while `50%off` doesn't. If the site takes free text containing `%`, drop `(25)?` or exempt that parameter.
- Start in Count. Clients that encode more than they should show up there.

---

## Appendix I: Sensitive-File Probes

AWS managed rule groups block only some sensitive-file paths. This is what blocks them in Linux operating system Version_2.6, Known bad inputs Version_1.26, and Core rule set Version_1.23. Other versions can differ.

| Rule | Paths it blocks |
|---|---|
| Linux operating system `LFI_URIPATH` | `/.env`, `/.env.production`, `/.env.local`, `/.env.bak`, `/.gitignore`, `/.gitconfig`, `/.htaccess`, `/.htpasswd`, `/.ssh/id_rsa`, `/.bash_history`, `/.bashrc`, `/.dockerignore`, `/wp-config.php`, `/composer.json`, `/config.php.bak` |
| Known bad inputs `ExploitablePaths_URIPATH` | `/.env`, `/.env.production`, `/.aws/config` |
| Core rule set `GenericLFI_URIPATH` | `/.aws/credentials`, `/foo/../.env` |
| Core rule set `RestrictedExtensions_URIPATH` | `/.env.bak`, `/config.bak`, `/config.ini`, `/app.log`, `/web.config`, `/config.php.bak` |

No AWS managed rule blocks `/.git/config`, `/.git/HEAD`, `/.DS_Store`, `/.svn/entries`, `/.npmrc`, `/.docker/config.json`, `/.vscode/settings.json`, `/.idea/workspace.xml`, `/.gitlab-ci.yml`, `/.travis.yml`, `/backup.zip`, `/db.sql`, `/docker-compose.yml`, or `/id_rsa`. `LFI_URIPATH` also blocks `composer.json` and `wp-config.php`, so a site that serves them gets false positives.

**Custom rule.** It blocks a path segment that starts with `.` outside `.well-known/` directories (nested ones too, such as Keycloak's `/realms/<realm>/.well-known/`), backup and dump extensions, and a few file names:

```json
{{
  "Name": "custom-sensitive-files",
  "Priority": "<place after the managed rule groups>",
  "Action": {{ "Block": {{}} }},
  "VisibilityConfig": {{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "custom-sensitive-files"
  }},
  "Statement": {{
    "OrStatement": {{
      "Statements": [
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "RegexMatchStatement": {{
                  "RegexString": "(^|/)\\.[^/]+",
                  "FieldToMatch": {{ "UriPath": {{}} }},
                  "TextTransformations": [
                    {{ "Priority": 0, "Type": "URL_DECODE" }},
                    {{ "Priority": 1, "Type": "URL_DECODE" }},
                    {{ "Priority": 2, "Type": "REMOVE_NULLS" }},
                    {{ "Priority": 3, "Type": "NORMALIZE_PATH" }},
                    {{ "Priority": 4, "Type": "LOWERCASE" }}
                  ]
                }}
              }},
              {{
                "NotStatement": {{
                  "Statement": {{
                    "ByteMatchStatement": {{
                      "SearchString": "/.well-known/",
                      "FieldToMatch": {{ "UriPath": {{}} }},
                      "PositionalConstraint": "CONTAINS",
                      "TextTransformations": [
                        {{ "Priority": 0, "Type": "URL_DECODE" }},
                        {{ "Priority": 1, "Type": "URL_DECODE" }},
                        {{ "Priority": 2, "Type": "REMOVE_NULLS" }},
                        {{ "Priority": 3, "Type": "NORMALIZE_PATH" }},
                        {{ "Priority": 4, "Type": "LOWERCASE" }}
                      ]
                    }}
                  }}
                }}
              }}
            ]
          }}
        }},
        {{
          "RegexMatchStatement": {{
            "RegexString": "(\\.(sql|dump|zip|tar|tgz|gz|7z|rar|bak|old|orig|swp)|(^|/)(docker-compose\\.ya?ml|id_rsa|id_ed25519))(/|;|$)",
            "FieldToMatch": {{ "UriPath": {{}} }},
            "TextTransformations": [
              {{ "Priority": 0, "Type": "URL_DECODE" }},
              {{ "Priority": 1, "Type": "URL_DECODE" }},
              {{ "Priority": 2, "Type": "REMOVE_NULLS" }},
              {{ "Priority": 3, "Type": "NORMALIZE_PATH" }},
              {{ "Priority": 4, "Type": "LOWERCASE" }}
            ]
          }}
        }}
      ]
    }}
  }}
}}
```

- The JSON shows `SearchString` as plain text; the API and CLI take it as base64: `/.well-known/` is `Ly53ZWxsLWtub3duLw==`.
- The exemption has the same transformations as the match, so `/.well-known/../.git/config` normalizes to `/.git/config` and doesn't skip the rule. `REMOVE_NULLS` keeps `/db.sql%00` from slipping past the end anchor, and `(/|;|$)` also catches a trailing slash and Java path parameters (`/db.sql;x`).
- Each of the three conditions carries five transformations at 10 WCU each.
- Start in Count. If the site serves a dotfile or one of these extensions on purpose, add its path as another exemption.
- The origin should still refuse these files. WAF is the second layer.
"""


APPENDIX_SECTIONS_ZH = r"""
---

# 附录

## 附录 A：ASN + UA 爬虫标记规则

这条规则放在 AntiDDoS AMR 和 Always-on Challenge **之前**。它给验证过的搜索引擎爬虫打上标签，后面的规则可以用 scope-down 把它们排除掉。JSON 里的 `SearchString` 写的是明文，API 和 CLI 要用 base64。

```json
{{
  "Name": "label-verified-crawlers",
  "Priority": "<place before AntiDDoS AMR>",
  "Action": {{
    "Count": {{}}
  }},
  "RuleLabels": [
    {{ "Name": "crawler:verified" }}
  ],
  "VisibilityConfig": {{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "label-verified-crawlers"
  }},
  "Statement": {{
    "OrStatement": {{
      "Statements": [
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "ByteMatchStatement": {{
                  "SearchString": "googlebot",
                  "FieldToMatch": {{ "SingleHeader": {{ "Name": "user-agent" }} }},
                  "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}],
                  "PositionalConstraint": "CONTAINS"
                }}
              }},
              {{ "AsnMatchStatement": {{ "AsnList": [15169] }} }}
            ]
          }}
        }},
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "ByteMatchStatement": {{
                  "SearchString": "bingbot",
                  "FieldToMatch": {{ "SingleHeader": {{ "Name": "user-agent" }} }},
                  "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}],
                  "PositionalConstraint": "CONTAINS"
                }}
              }},
              {{ "AsnMatchStatement": {{ "AsnList": [8075] }} }}
            ]
          }}
        }},
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "ByteMatchStatement": {{
                  "SearchString": "yandexbot",
                  "FieldToMatch": {{ "SingleHeader": {{ "Name": "user-agent" }} }},
                  "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}],
                  "PositionalConstraint": "CONTAINS"
                }}
              }},
              {{ "AsnMatchStatement": {{ "AsnList": [13238, 208722] }} }}
            ]
          }}
        }}
      ]
    }}
  }}
}}
```

已确认的 ASN：Google 15169，Bing 8075，Yandex 13238 和 208722。其他搜索引擎（百度、Yahoo Japan 等）请先查它们官方文档里的最新 ASN 再添加。

---

## 附录 B：双 AntiDDoS AMR 实例

浏览器流量和 API、原生 App 流量共用同一个 host，又需要不同的 AntiDDoS 策略时使用。如果 API 流量有自己的 host，一个实例就够了：在豁免正则里把这个 host 排除在 Challenge 之外（`^api\.example\.com\/`），AWS WAF 拿它去匹配"host 加规范化后的路径"。如果这个 host 还有自己的 distribution 或负载均衡，给它单独建一个 Web ACL 更简单。

1. **在两个 AMR 实例之前加一条 Count+Label 规则**，给浏览器请求打标签：`GET` 并且 `Accept` 包含 `text/html`，标签 `custom:browser-request`。这条规则的 priority 数字要比两个 AMR 实例都小。
2. **AMR 实例 1（浏览器流量）**：scope-down 匹配浏览器标签，并排除爬虫标签。启用 `ChallengeAllDuringEvent`，Block 灵敏度 LOW（默认值）。
3. **AMR 实例 2（API 和原生 App 流量）**：scope-down 排除浏览器标签。把 `ChallengeAllDuringEvent` 改成 Count，Block 灵敏度 MEDIUM（这类流量用不了 Challenge，要靠提高 Block 灵敏度补上）。
4. **操作方法**：AWS 控制台不允许把同一个托管规则组加两次。先复制现有 AMR 规则的 JSON，在 Web ACL 里新建一条**自定义规则**，打开 **JSON 编辑器**，粘贴复制的 JSON，把 `Name` 和 `MetricName` 改成不重复的值（如 `AntiDDoS-API`），再保存。

代价是：`Accept: */*` 这类不像浏览器页面加载的攻击请求会落到实例 2，只会被 Block，不会被 Challenge。即便如此，也比把 `ChallengeAllDuringEvent` 整个关掉好得多。

排除爬虫的 scope-down（如果 AMR 已经有 scope-down，用 `AndStatement` 合并进去）：

```json
{{
  "NotStatement": {{
    "Statement": {{
      "LabelMatchStatement": {{
        "Scope": "LABEL",
        "Key": "crawler:verified"
      }}
    }}
  }}
}}
```

---

## 附录 C：Landing page 的 Always-on Challenge

在 landing page 上主动防 DDoS，用两条规则：

1. **标签规则**（Count+Label）：匹配 landing page 的 URI（如 `/`、`/login`、`/signup`），加标签 `custom:landing-page`。动作是 Count，请求继续往下走。
2. **Challenge 规则**：匹配 `custom:landing-page` 标签，动作是 Challenge。再加一个针对 `crawler:verified` 标签的 `NotStatement`，把验证过的爬虫排除掉。

landing page 的 URI 列表要按自己的应用来定。

token 免疫时间建议至少 4 小时（14400 秒）。真实用户完成一次 JS 验证后，整个免疫期内都不会再被打断。

---

## 附录 D：规则顺序参考

| 位置 | 规则类型 | 原因 |
|------|----------|------|
| 1 | IP 白名单（Allow，只用 IP set） | 可信 IP 跳过所有规则 |
| 2 | IP 黑名单（Block） | 已知恶意 IP 直接拦截 |
| 3 | Count+Label 规则 | 给流量打标签，供后面的规则做 scope-down |
| 4 | AntiDDoS AMR | 要看到全部流量才能建准基线 |
| 5 | IP 信誉规则组 | WCU 低，先过滤已知恶意 IP |
| 6 | 匿名 IP 规则组 | 过滤匿名 IP 和云主机 IP |
| 7 | 限速规则 | 放在 Challenge 之前 |
| 8 | Always-on Challenge | landing page 的主动 DDoS 防护 |
| 9 | 自定义规则 | 业务相关的逻辑 |
| 10 | 应用层规则组（CRS、KnownBadInputs） | OWASP Top 10 防护 |
| 11 | Bot Control / ATP / ACFP | 按请求数收费，放在最后 |

原则：产生标签的规则放在使用标签的规则前面，AntiDDoS AMR 尽量靠前，便宜的规则放在贵的前面。除了附录 B 的双实例，AntiDDoS AMR 只该有一种 scope-down：排除验证过的爬虫（附录 A）。

这个顺序针对默认 Allow 的 Web ACL。默认 Block 时，Allow 规则就是入口：内容检测规则组（第 10 位）要放到它们前面，否则只能检查到本来就会被拦的流量。

---

## 附录 E：WCU 容量

{wcu_text}

按建议改完规则后，确认新的 WCU 总量没有超过 5000，这是固定上限。Web ACL 的基础价格包含 1,500 WCU，超出部分每 500 WCU 加收一笔按请求计的费用（见 AWS WAF 价格页），Shield Advanced 也只覆盖 1,500 WCU 以内的标准 AWS WAF 费用。查看位置：AWS 控制台 → WAF → Web ACLs → 选中这个 Web ACL，概览页里有容量。

---

## 附录 F：常见的 override 建议

添加或检查托管规则组时，可以参考这些常见的 override：

**AWSManagedRulesCommonRuleSet (CRS)：**
- 把 `SizeRestrictions_BODY` 设为 **Count**。这条规则会拦截超过 8KB 的请求体，在文件上传、大 payload 的 API 和内容较多的表单提交上经常误报。

**AWSManagedRulesBotControlRuleSet（Bot Control COMMON 级别）：**
- `SignalNonBrowserUserAgent` 和 `CategoryHttpLibrary` 默认会拦非浏览器的 User-Agent。如果有原生 App（okhttp、gohttp）、API 客户端、合作方或监控访问这个 Web ACL，把两条都设为 **Count**，或者用 scope-down 让这些流量不进 Bot Control。
- 只有浏览器访问的站点，两条都保持默认的 Block。

**AWSManagedRulesAnonymousIpList：**
- 仔细评估 `HostingProviderIPList`。默认 Block 会拦截来自云平台和主机托管商的请求。如果你的客户端可能从云上发起（例如经过云代理的企业用户、SaaS 集成），把它设为 **Count**。不要设为 Allow，那样会让云上的攻击流量跳过后面所有规则。

---

## 附录 G：自定义规则里的编码和解码

自定义规则要匹配的，应该是源站最终处理的那个字符串。源站把 `/%69nternal/` 解码成 `/internal/` 再处理，规则检查路径时也得先解码，否则永远看不到 `/internal/`。

**两个方向出错，代价不一样。** 规则解码得比源站少，就是 fail open：Block 规则会漏掉 `/%69nternal/`、`%2569` 这类编码变体，没做规范化的 Allow 规则或豁免条件还会放过 `/public/../admin`。这些情况在日志里看不出来。规则解码得比源站多，就是 fail closed：Block 规则可能拦下源站当普通数据处理的请求，比如路径段里的 `%2F`，Allow 规则则会放得更少。这些是误报，规则在 Count 下运行时就能看到。所以下面的参考写法偏向多解码。

**AWS WAF 为什么默认不解码。** 不加文本转换时，WAF 按客户端发来的原样检查 URI 路径，body 也按纯文本检查。WAF 不知道源站怎么解码请求，各家框架连查询参数在哪里断开都不一样，比如 API Gateway REST API 还会按 `;` 拆分。有些规则又必须看原始字节，比如附录 H 那条。所以用哪些转换，交给写规则的人决定，目标是让 WAF 按应用理解请求的方式去检查请求。

**CloudFront** 只在选择 cache behavior 时规范化路径，转给源站的还是原始路径。`..`、`//` 和编码字符会原样到达源站，除非 CloudFront Functions 或 Lambda@Edge 改写了路径。写规则时，也按 WAF 看到的路径没有规范化来处理。

**托管规则组** 自己决定用哪些转换，用户改不了。这里说的都是自定义规则。

**参考写法。** 转换按 priority 从小到大执行。每个转换 10 WCU，一条语句最多 10 个转换。几个值可以写进同一个正则或 regex pattern set，共用一套转换。

| 字段 | 参考转换链 | 说明 |
|---|---|---|
| `UriPath` | `URL_DECODE`、`URL_DECODE`、`REMOVE_NULLS`、`NORMALIZE_PATH`、`LOWERCASE` | |
| `QueryString`、`SingleQueryArgument`、`AllQueryArguments` | `URL_DECODE`、`URL_DECODE`、`REMOVE_NULLS`、`LOWERCASE` | 不加 `NORMALIZE_PATH`，它会改写参数值里的 `//` 和 `../`。按参数检查时，WAF 拆的是原始查询串，`%26` 和 `%3D` 不会被当成参数分隔符。在 `PreParseTextTransformations` 里加 `URL_DECODE` 才会，`REPLACE_SEMICOLONS_WITH_AMPERSANDS`（只能用作 pre-parse 转换）则像 API Gateway REST API 那样按 `;` 拆分。pre-parse 转换只对 `SingleQueryArgument` 和 `AllQueryArguments` 生效 |
| 表单 `Body` | `URL_DECODE`、`URL_DECODE`、`REMOVE_NULLS`、`LOWERCASE` | 表单 body 和查询串一样是 URL 编码的 |
| `JsonBody` | 应用会解开 JSON 字符串转义时加 `JS_DECODE` | `JS_DECODE` 能解 `\u0069` 这类 JavaScript 转义 |
| Header、cookie | 检查攻击 payload 时，应用会 URL 解码这个值就用查询串那套；其他情况不区分大小写时加 `LOWERCASE` | 很多框架会对 cookie 值做 URL 解码，对 header 解码的很少。User-Agent 这类客户端随便填的值，规则只拦得住不改它的客户端，解不解码都一样 |

**几种变体。** 按源站的行为选，每种都有代价。
- 解一次还是两次：第二次解码是为了防 `%2569` 这类双重编码，以防源站或它前面的代理解了两次。代价是多 10 WCU，用户输入的字面 `%41`（发出来是 `%2541`）也会被解成 `A`。
- 用 `URL_DECODE_UNI` 代替 `URL_DECODE`：多解 IIS 风格的 `%uXXXX`，源站是 IIS 时有用。代价是，已经废弃的 JavaScript `escape()` 会把非 ASCII 文字编成 `%uXXXX`，不在全角区间的只保留低字节。中文就变成一串随机的 ASCII 字符，可能碰巧匹配上某个 pattern。
- 用 `NORMALIZE_PATH_WIN` 代替 `NORMALIZE_PATH`：多一步，把 `\` 换成 `/`，源站把 `\` 当路径分隔符时（Windows、IIS）有用。代价是路径里正常的 `\` 也会被改掉。只用在路径上。

**顺序。** 先解码，再清理。如果把 `LOWERCASE` 放在解码前面，`%49nternal` 解码后是 `Internal`，大写留了下来。如果把 `NORMALIZE_PATH` 放在解码前面，`/%2e%2e/` 不会被折叠。如果把 `REMOVE_NULLS` 放在解码前面，`%00` 解出来的空字节去不掉。

**开头的 `../`。** `NORMALIZE_PATH` 不处理路径最开头的 `../`，所以 `/../admin` 经过整套转换还是原样，而大多数源站会把它解析成 `/admin`。Core rule set 的 `GenericLFI_URIPATH` 设为 Block 时会检查 `../` 这类路径穿越（附录 I 里 `/foo/../.env` 就是它拦的）。

**路径参数。** Tomcat 这类 Java servlet 容器在路由前会去掉 `;` 后面的路径参数，所以 `/admin;x=1` 会到达 `/admin`。没有哪个文本转换能去掉它们。用 `EXACTLY`、`ENDS_WITH`，或者用 `$`、`(/|$)` 结尾的正则匹配 `/admin` 的规则，都会漏掉这种请求。源站是这类容器时，匹配结尾写成 `(/|;|$)`，或者在用不到 `;` 的路径上直接拦截它。Tomcat 还会把 `..;` 当成 `..`，所以 `/public/..;/admin` 能绕过本来有 `NORMALIZE_PATH` 保护的前缀 Allow 或豁免条件。

**放行请求的规则** 也要规范化。Allow 规则或 NOT 条件写的是 `STARTS_WITH /public/`，又没有 `NORMALIZE_PATH`，`/public/../admin` 也会命中。只做 `NORMALIZE_PATH` 不先解码的话，`/public/%2e%2e/admin` 还是以 `/public/` 开头。这类条件要先解码，再规范化。

**不能解码的规则。** 有的规则要找的就是编码本身，比如 `%00`，或者附录 H 里编码后的字母。一解码，它要找的东西就没了。pattern 里写了 `%XX` 的条件，评审不会报缺少解码。

所有改动都先在 Count 下观察，再切成 Block。

---

## 附录 H：拦截编码后的非保留字符和空字节

RFC 3986 第 2.3 节规定，生成 URI 时不应该对字母、数字和 `-`、`.`、`_`、`~` 做百分号编码。浏览器和常见的 HTTP 库都照这个做。所以请求里出现 `%69`（`i`）或 `%2e`（`.`），通常是扫描器在试着绕过规则，比如 `/%69nternal/`、`%2e%2e/`。这条规则在所有路径和查询串上拦编码后的字母、数字和点，不管其他规则用了哪些转换。`//`、`/./`、大小写变化和 IIS 风格的 `%u0069` 它管不到。

不要一律拦 `%`。正常请求里有很多编码：空格 `%20`，中文等非 ASCII 字符 `%E4%B8%AD`，当作数据用的保留字符 `%26`、`%3D`、`%2F`、`%3A`、`%40`，比如 `url=https%3A%2F%2F...`。

```json
{{
  "Name": "block-encoded-unreserved",
  "Priority": "<place early, ahead of any Allow rule that matches on the path>",
  "Action": {{ "Block": {{}} }},
  "VisibilityConfig": {{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "block-encoded-unreserved"
  }},
  "Statement": {{
    "OrStatement": {{
      "Statements": [
        {{
          "RegexMatchStatement": {{
            "RegexString": "%(25)?(3[0-9]|[46][1-9a-f]|[57][0-9a]|2[de]|5f|00)",
            "FieldToMatch": {{ "UriPath": {{}} }},
            "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}]
          }}
        }},
        {{
          "RegexMatchStatement": {{
            "RegexString": "%(25)?(3[0-9]|[46][1-9a-f]|[57][0-9a]|2[de]|5f|00)",
            "FieldToMatch": {{ "QueryString": {{}} }},
            "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}]
          }}
        }}
      ]
    }}
  }}
}}
```

- 只做 `LOWERCASE`，`%4A` 和 `%4a` 都能匹配。不要加 `URL_DECODE`，这条规则检查的就是编码本身。
- 正则各段：`3[0-9]` 是数字；`4[1-9a-f]`、`5[0-9a]` 是 `A` 到 `Z`；`6[1-9a-f]`、`7[0-9a]` 是 `a` 到 `z`；`2[de]`、`5f` 是 `-`、`.`、`_`；`00` 是空字节，URL 里没有任何正当用途。可选的 `25` 用来抓双重编码，比如 `%2569`。
- 故意没拦 `~`（`%7E`）。Java 的 `URLEncoder` 会编码它，Python 3.7 之前也会。
- 用户输入的字面 `%`，如果后面两个字符正好拼出上面这些编码，也会被可选的 `25` 命中：搜索 `50%30` 发出来是 `50%2530`，会命中，`50%off` 不会。站点有允许输入 `%` 的自由文本（比如搜索框）的话，去掉 `(25)?`，或者排除那个参数。
- 先用 Count。编码过度的客户端会在这一阶段暴露出来。

---

## 附录 I：敏感文件探测

AWS 托管规则组只拦得住一部分敏感文件路径。下表是 Linux operating system Version_2.6、Known bad inputs Version_1.26、Core rule set Version_1.23 里拦截这些路径的规则，其他版本可能不同。

| 规则 | 拦截的路径 |
|---|---|
| Linux operating system `LFI_URIPATH` | `/.env`、`/.env.production`、`/.env.local`、`/.env.bak`、`/.gitignore`、`/.gitconfig`、`/.htaccess`、`/.htpasswd`、`/.ssh/id_rsa`、`/.bash_history`、`/.bashrc`、`/.dockerignore`、`/wp-config.php`、`/composer.json`、`/config.php.bak` |
| Known bad inputs `ExploitablePaths_URIPATH` | `/.env`、`/.env.production`、`/.aws/config` |
| Core rule set `GenericLFI_URIPATH` | `/.aws/credentials`、`/foo/../.env` |
| Core rule set `RestrictedExtensions_URIPATH` | `/.env.bak`、`/config.bak`、`/config.ini`、`/app.log`、`/web.config`、`/config.php.bak` |

`/.git/config`、`/.git/HEAD`、`/.DS_Store`、`/.svn/entries`、`/.npmrc`、`/.docker/config.json`、`/.vscode/settings.json`、`/.idea/workspace.xml`、`/.gitlab-ci.yml`、`/.travis.yml`、`/backup.zip`、`/db.sql`、`/docker-compose.yml`、`/id_rsa` 没有任何 AWS 托管规则拦截。`LFI_URIPATH` 还会命中 `composer.json` 和 `wp-config.php`，站点正常提供这两个文件的话会有误报。

**自定义规则。** 拦截 `.well-known/` 目录以外以 `.` 开头的路径段（嵌套的 `.well-known/` 也放行，比如 Keycloak 的 `/realms/<realm>/.well-known/`）、备份和导出文件的扩展名，以及几个文件名：

```json
{{
  "Name": "custom-sensitive-files",
  "Priority": "<place after the managed rule groups>",
  "Action": {{ "Block": {{}} }},
  "VisibilityConfig": {{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "custom-sensitive-files"
  }},
  "Statement": {{
    "OrStatement": {{
      "Statements": [
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "RegexMatchStatement": {{
                  "RegexString": "(^|/)\\.[^/]+",
                  "FieldToMatch": {{ "UriPath": {{}} }},
                  "TextTransformations": [
                    {{ "Priority": 0, "Type": "URL_DECODE" }},
                    {{ "Priority": 1, "Type": "URL_DECODE" }},
                    {{ "Priority": 2, "Type": "REMOVE_NULLS" }},
                    {{ "Priority": 3, "Type": "NORMALIZE_PATH" }},
                    {{ "Priority": 4, "Type": "LOWERCASE" }}
                  ]
                }}
              }},
              {{
                "NotStatement": {{
                  "Statement": {{
                    "ByteMatchStatement": {{
                      "SearchString": "/.well-known/",
                      "FieldToMatch": {{ "UriPath": {{}} }},
                      "PositionalConstraint": "CONTAINS",
                      "TextTransformations": [
                        {{ "Priority": 0, "Type": "URL_DECODE" }},
                        {{ "Priority": 1, "Type": "URL_DECODE" }},
                        {{ "Priority": 2, "Type": "REMOVE_NULLS" }},
                        {{ "Priority": 3, "Type": "NORMALIZE_PATH" }},
                        {{ "Priority": 4, "Type": "LOWERCASE" }}
                      ]
                    }}
                  }}
                }}
              }}
            ]
          }}
        }},
        {{
          "RegexMatchStatement": {{
            "RegexString": "(\\.(sql|dump|zip|tar|tgz|gz|7z|rar|bak|old|orig|swp)|(^|/)(docker-compose\\.ya?ml|id_rsa|id_ed25519))(/|;|$)",
            "FieldToMatch": {{ "UriPath": {{}} }},
            "TextTransformations": [
              {{ "Priority": 0, "Type": "URL_DECODE" }},
              {{ "Priority": 1, "Type": "URL_DECODE" }},
              {{ "Priority": 2, "Type": "REMOVE_NULLS" }},
              {{ "Priority": 3, "Type": "NORMALIZE_PATH" }},
              {{ "Priority": 4, "Type": "LOWERCASE" }}
            ]
          }}
        }}
      ]
    }}
  }}
}}
```

- JSON 里的 `SearchString` 写的是明文，API 和 CLI 要用 base64，`/.well-known/` 是 `Ly53ZWxsLWtub3duLw==`。
- 豁免条件和匹配条件用同一套转换，所以 `/.well-known/../.git/config` 规范化成 `/.git/config`，跳不过这条规则。`REMOVE_NULLS` 防止 `/db.sql%00` 绕过结尾的锚点，`(/|;|$)` 还能拦住结尾多一个斜杠和 Java 路径参数（`/db.sql;x`）的写法。
- 三个条件各有五个转换，每个 10 WCU。
- 先用 Count。站点确实要提供某个 dotfile 或这些扩展名的文件，就把它的路径加成另一个豁免条件。
- 源站本身也要拒绝这些文件，WAF 只是第二层。
"""


def main():
    if len(sys.argv) < 2:
        fatal("Usage: waf-generate-appendix.py <output_dir> [--lang en|zh]")

    output_dir = sys.argv[1]
    zh = "--lang" in sys.argv and sys.argv[sys.argv.index("--lang") + 1:][:1] == ["zh"]
    summary_path = work_path(output_dir, "waf-summary.json")

    # Read WCU from summary
    wcu_text = ("导出文件里没有 WCU 容量，添加规则前请在 AWS 控制台确认。" if zh else
                "WCU capacity unknown (not in export JSON). Verify in AWS Console before adding rules.")
    ddos = probes = True
    if os.path.isfile(summary_path):
        try:
            summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
            ddos = summary.get("web_acl", {}).get("default_action") != "block" or any(
                (r.get("managed") or {}).get("group_name") == "AWSManagedRulesAntiDDoSRuleSet"
                for r in summary.get("rules", []))
            # Sensitive-file probes only reach the origin when the Web ACL allows by default
            probes = summary.get("web_acl", {}).get("default_action") != "block"
            capacity = summary.get("web_acl", {}).get("capacity")
            if capacity is not None:
                wcu_text = (f"当前 WCU：**{capacity}** / 5000。" if zh else
                            f"Current WCU: **{capacity}** / 5000.")
                if capacity > 1500:
                    wcu_text += ("已经超过 1,500。" if zh else " That's already above 1,500.")
        except (json.JSONDecodeError, OSError):
            pass  # Fall back to unknown

    # Template braces are escaped as {{ }} for readability; undo after substitution
    content = ((APPENDIX_SECTIONS_ZH if zh else APPENDIX_SECTIONS).replace("{wcu_text}", wcu_text)
               .replace("{{", "{").replace("}}", "}"))
    if not ddos:
        # Drop B and C with the rule that follows each
        content = re.sub(r"^## (?:Appendix|附录) [BC][:：].*?(?=^## )", "", content, flags=re.M | re.S)
    if not probes:
        # I is the last section
        content = re.sub(r"\n---\n+## (?:Appendix|附录) I[:：].*", "\n", content, flags=re.S)
    sections = len(re.findall(r"^## (?:Appendix|附录) [A-I]", content, re.M))

    output_file = work_path(output_dir, "appendix.md")
    try:
        Path(output_file).write_text(content, encoding="utf-8")
    except OSError as e:
        fatal(f"Failed to write {output_file}: {e}")

    print(f"Generated appendix with {sections} sections", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"OUTPUT_FILE: {output_file}")
    print(f"SECTIONS: {sections}")


if __name__ == "__main__":
    main()
