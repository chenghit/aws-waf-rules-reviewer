#!/usr/bin/env python3
"""Generate fixed appendix content for WAF review reports.

The LLM decides which sections to reference. Dynamic parts: WCU capacity from
waf-summary.json, and Appendix B/C (Anti-DDoS patterns) only for Web ACLs that
have Anti-DDoS AMR or face the internet with a default Allow. Letters stay
fixed so references don't shift.
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

Place this rule **before** AntiDDoS AMR and Always-on Challenge. It labels verified search engine crawlers so downstream rules can exclude them via scope-down.

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

When browser and native app traffic need different AntiDDoS strategies. If the native app traffic has its own host on its own distribution or load balancer, a separate Web ACL for it is simpler than two instances.

1. **Add a Count+Label rule before both AMR instances** to label native app traffic (e.g., label `native-app:identified`). This rule must have a higher priority (lower number) than both AMR instances.
2. **AMR instance 1 (browser traffic)**: scope-down excludes the native app label. `ChallengeAllDuringEvent` enabled. Block sensitivity: LOW (default).
3. **AMR instance 2 (native app traffic)**: scope-down matches the native app label only. `ChallengeAllDuringEvent` disabled. Block sensitivity: MEDIUM (since Challenge is unavailable, raise Block sensitivity for adequate protection).
4. **Implementation**: The AWS console does not allow adding the same managed rule group twice. First copy the existing AMR rule's JSON. Then create a new **custom rule** in the Web ACL, open its **JSON editor**, paste the copied AMR JSON, change `Name` and `MetricName` to unique values (e.g., `AntiDDoS-NativeApp`), then save.

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

Key principles: label producers before consumers, AntiDDoS AMR as early as possible, cheaper rules before expensive ones.

This order is for a Web ACL that allows by default. When the default action is Block, the Allow rules are the way in: put content inspection groups (position 10) ahead of them, or they only see traffic that is blocked anyway.

---

## Appendix E: WCU Capacity Reminder

{wcu_text}

After implementing any recommended changes, verify the new WCU total does not exceed 5000. Check in the AWS Console: WAF → Web ACLs → select your Web ACL → the capacity is shown in the overview.

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
"""


APPENDIX_SECTIONS_ZH = r"""
---

# 附录

## 附录 A：ASN + UA 爬虫标记规则

这条规则放在 AntiDDoS AMR 和 Always-on Challenge **之前**。它给验证过的搜索引擎爬虫打上标签，后面的规则可以用 scope-down 把它们排除掉。

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

浏览器流量和原生 App 流量需要不同的 AntiDDoS 策略时使用。如果原生 App 流量走的是单独的 host，并且有自己的 distribution 或负载均衡，给它单独建一个 Web ACL 比两个实例更简单。

1. **在两个 AMR 实例之前加一条 Count+Label 规则**，给原生 App 流量打标签（如 `native-app:identified`）。这条规则的 priority 数字要比两个 AMR 实例都小。
2. **AMR 实例 1（浏览器流量）**：scope-down 排除原生 App 标签。启用 `ChallengeAllDuringEvent`，Block 灵敏度 LOW（默认值）。
3. **AMR 实例 2（原生 App 流量）**：scope-down 只匹配原生 App 标签。关闭 `ChallengeAllDuringEvent`，Block 灵敏度 MEDIUM（这类流量用不了 Challenge，要靠提高 Block 灵敏度补上）。
4. **操作方法**：AWS 控制台不允许把同一个托管规则组加两次。先复制现有 AMR 规则的 JSON，在 Web ACL 里新建一条**自定义规则**，打开 **JSON 编辑器**，粘贴复制的 JSON，把 `Name` 和 `MetricName` 改成不重复的值（如 `AntiDDoS-NativeApp`），再保存。

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

原则：产生标签的规则放在使用标签的规则前面，AntiDDoS AMR 尽量靠前，便宜的规则放在贵的前面。

这个顺序针对默认 Allow 的 Web ACL。默认 Block 时，Allow 规则就是入口：内容检测规则组（第 10 位）要放到它们前面，否则只能检查到本来就会被拦的流量。

---

## 附录 E：WCU 容量

{wcu_text}

按建议改完规则后，确认新的 WCU 总量没有超过 5000。查看位置：AWS 控制台 → WAF → Web ACLs → 选中这个 Web ACL，概览页里有容量。

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
    ddos = True
    if os.path.isfile(summary_path):
        try:
            summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
            ddos = summary.get("web_acl", {}).get("default_action") != "block" or any(
                (r.get("managed") or {}).get("group_name") == "AWSManagedRulesAntiDDoSRuleSet"
                for r in summary.get("rules", []))
            capacity = summary.get("web_acl", {}).get("capacity")
            if capacity is not None:
                wcu_text = (f"当前 WCU：**{capacity}** / 5000。" if zh else
                            f"Current WCU: **{capacity}** / 5000.")
        except (json.JSONDecodeError, OSError):
            pass  # Fall back to unknown

    # Template braces are escaped as {{ }} for readability; undo after substitution
    content = ((APPENDIX_SECTIONS_ZH if zh else APPENDIX_SECTIONS).replace("{wcu_text}", wcu_text)
               .replace("{{", "{").replace("}}", "}"))
    if not ddos:
        # Drop B and C with the rule that follows each
        content = re.sub(r"^## (?:Appendix|附录) [BC][:：].*?(?=^## )", "", content, flags=re.M | re.S)
    sections = len(re.findall(r"^## (?:Appendix|附录) [A-F]", content, re.M))

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
