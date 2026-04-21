# Examples

**For English speakers**: To run this example, start a chat session with your AI coding tool and use a prompt like:
> Please review my AWS WAF configuration. The file is at examples/web-acl-example.json. Save the report to examples/.

---

## 输入

- `web-acl-example.json` — 组装的 27 条规则 WAF 配置，涵盖 AntiDDoS AMR、Bot Control、rate-based、自定义 Allow/Challenge/Count 规则等典型场景

## 使用的 Prompt

```
请检查我的aws waf配置是否合理。文件是本地目录 examples/web-acl-example.json。输出的report也请写入到 examples/
```

使用 Kiro CLI + Claude Sonnet 4.6 (1M) 生成。

## 输出

**你只需要看这一个文件：**

- **`waf-review/waf-review-report.md`** — 完整的评审报告（21 个发现，含摘要表、详细分析、Mermaid 规则执行流程图）

其他文件都是流水线的中间产物，不需要阅读：

| 文件 | 用途 |
|------|------|
| `waf-review/waf-summary.json` | 预处理后的结构化规则摘要 |
| `waf-review/pre-checks.json` | 机械预检结果 |
| `waf-review/appendix.md` | 附录内容（规则 JSON 模板、操作步骤等） |
| `waf-review/scripted-findings.md` | 脚本生成的 18 个确定性发现 |
| `waf-review/findings-metadata.json` | 发现元数据（LLM 分析哪些 section、issue 编号等） |
| `waf-review/issue-rule-mapping.json` | Issue 与规则的映射关系（供 Mermaid 标注用） |
| `waf-review/mermaid-base.md` | 基础 Mermaid 图（无标注） |
| `waf-review/mermaid-metadata.json` | Mermaid 节点元数据 |
| `waf-review/mermaid-final.md` | 标注后的 Mermaid 图（已合并到报告末尾） |
| `waf-review/validation.json` | 报告结构验证结果 |

## 发现概览

本次评审共产出 21 个发现：18 个由脚本确定性生成，3 个由 LLM 分析产出。

| 严重程度 | 数量 | 来源 |
|---------|------|------|
| 🔴 Critical | 3 | 脚本 |
| 🟡 Medium | 11 | 脚本 8 + LLM 3 |
| 🟢 Low | 4 | 脚本 |
| 🔵 Awareness | 3 | 脚本 |

LLM 仅分析了 3 个需要判断力的检查项（Bot Control 策略、Cookie 逻辑、跨规则修复影响），其余全部由脚本处理。
