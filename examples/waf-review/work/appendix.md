
---

# 附录

## 附录 A：ASN + UA 爬虫标记规则

这条规则放在 AntiDDoS AMR 和 Always-on Challenge **之前**。它给验证过的搜索引擎爬虫打上标签，后面的规则可以用 scope-down 把它们排除掉。

```json
{
  "Name": "label-verified-crawlers",
  "Priority": "<place before AntiDDoS AMR>",
  "Action": {
    "Count": {}
  },
  "RuleLabels": [
    { "Name": "crawler:verified" }
  ],
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "label-verified-crawlers"
  },
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "AndStatement": {
            "Statements": [
              {
                "ByteMatchStatement": {
                  "SearchString": "googlebot",
                  "FieldToMatch": { "SingleHeader": { "Name": "user-agent" } },
                  "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
                  "PositionalConstraint": "CONTAINS"
                }
              },
              { "AsnMatchStatement": { "AsnList": [15169] } }
            ]
          }
        },
        {
          "AndStatement": {
            "Statements": [
              {
                "ByteMatchStatement": {
                  "SearchString": "bingbot",
                  "FieldToMatch": { "SingleHeader": { "Name": "user-agent" } },
                  "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
                  "PositionalConstraint": "CONTAINS"
                }
              },
              { "AsnMatchStatement": { "AsnList": [8075] } }
            ]
          }
        },
        {
          "AndStatement": {
            "Statements": [
              {
                "ByteMatchStatement": {
                  "SearchString": "yandexbot",
                  "FieldToMatch": { "SingleHeader": { "Name": "user-agent" } },
                  "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
                  "PositionalConstraint": "CONTAINS"
                }
              },
              { "AsnMatchStatement": { "AsnList": [13238, 208722] } }
            ]
          }
        }
      ]
    }
  }
}
```

已确认的 ASN：Google 15169，Bing 8075，Yandex 13238 和 208722。其他搜索引擎（百度、Yahoo Japan 等）请先查它们官方文档里的最新 ASN 再添加。

---

## 附录 B：双 AntiDDoS AMR 实例

浏览器流量和原生 App 流量需要不同的 AntiDDoS 策略时使用：

1. **在两个 AMR 实例之前加一条 Count+Label 规则**，给原生 App 流量打标签（如 `native-app:identified`）。这条规则的 priority 数字要比两个 AMR 实例都小。
2. **AMR 实例 1（浏览器流量）**：scope-down 排除原生 App 标签。启用 `ChallengeAllDuringEvent`，Block 灵敏度 LOW（默认值）。
3. **AMR 实例 2（原生 App 流量）**：scope-down 只匹配原生 App 标签。关闭 `ChallengeAllDuringEvent`，Block 灵敏度 MEDIUM（这类流量用不了 Challenge，要靠提高 Block 灵敏度补上）。
4. **操作方法**：AWS 控制台不允许把同一个托管规则组加两次。先复制现有 AMR 规则的 JSON，在 Web ACL 里新建一条**自定义规则**，打开 **JSON 编辑器**，粘贴复制的 JSON，把 `Name` 和 `MetricName` 改成不重复的值（如 `AntiDDoS-NativeApp`），再保存。

排除爬虫的 scope-down（如果 AMR 已经有 scope-down，用 `AndStatement` 合并进去）：

```json
{
  "NotStatement": {
    "Statement": {
      "LabelMatchStatement": {
        "Scope": "LABEL",
        "Key": "crawler:verified"
      }
    }
  }
}
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
| 1 | IP 白名单（Allow） | 可信 IP 跳过所有规则 |
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

---

## 附录 E：WCU 容量

当前 WCU：**435** / 5000。

按建议改完规则后，确认新的 WCU 总量没有超过 5000。查看位置：AWS 控制台 → WAF → Web ACLs → 选中这个 Web ACL，概览页里有容量。

---

## 附录 F：常见的 override 建议

添加或检查托管规则组时，可以参考这些常见的 override：

**AWSManagedRulesCommonRuleSet (CRS)：**
- 把 `SizeRestrictions_BODY` 设为 **Count**。这条规则会拦截超过 8KB 的请求体，在文件上传、大 payload 的 API 和内容较多的表单提交上经常误报。

**AWSManagedRulesBotControlRuleSet（Bot Control COMMON 级别）：**
- 把 `SignalNonBrowserUserAgent` 设为 **Count**。默认 Block 会拦掉正常的非浏览器客户端（用 okhttp、gohttp 的原生 App，API 客户端，监控工具）。
- 把 `CategoryHttpLibrary` 设为 **Count**。原因同上，原生 App 和 API 客户端用的 HTTP 库也会被拦。

**AWSManagedRulesAnonymousIpList：**
- 仔细评估 `HostingProviderIPList`。默认 Block 会拦截来自云平台和主机托管商的请求。如果你的客户端可能从云上发起（例如经过云代理的企业用户、SaaS 集成），把它设为 **Count**。不要设为 Allow，那样会让云上的攻击流量跳过后面所有规则。
