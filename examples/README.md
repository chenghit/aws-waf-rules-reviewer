# Examples

**For English speakers**: To run this example, start a chat session with your AI coding tool and use a prompt like:
> Please review my AWS WAF configuration. The file is at examples/web-acl-example.json. Save the report to examples/.

---

## 输入

- `web-acl-example.json`：组装的 27 条规则 WAF 配置，涵盖 AntiDDoS AMR、Bot Control、rate-based、自定义 Allow/Challenge/Count 规则等典型场景。域名都是 `example.com`，账号 ID 是 `111111111111`，没有真实数据

## 使用的 Prompt

```
请检查我的aws waf配置是否合理。文件是本地目录 examples/web-acl-example.json。输出的report也请写入到 examples/
```

使用 Claude Code + Claude Opus 5.5 生成（v0.7.1），总耗时约 9.6 分钟，其中 LLM 分析约 7.7 分钟，自审约 1.4 分钟，脚本步骤合计不到 10 秒。

## 输出

**只需要看这一个文件：**

- **`waf-review/waf-review-report.html`**：完整的评审报告，浏览器直接打开。包含摘要表、每个发现的详细分析和规则执行流程，Issue 编号可以点击跳转
- `waf-review/waf-review-report.md`：同一份报告的 Markdown 版本，用来修改。改完让 agent 重新生成 HTML

`waf-review/work/` 里是流水线的中间产物，不需要阅读：

| 文件 | 用途 |
|------|------|
| `work/waf-summary.json` | 预处理后的结构化规则摘要 |
| `work/pre-checks.json` | 机械预检结果 |
| `work/appendix.md` | 附录内容（规则 JSON 模板、操作步骤等） |
| `work/scripted-findings.md` | 脚本生成的 17 个确定性发现 |
| `work/findings-metadata.json` | 发现元数据（LLM 分析哪些 section、issue 编号等） |
| `work/issue-rule-mapping.json` | Issue 与规则的映射关系（供流程图标注用） |
| `work/mermaid-base.md` | 基础 Mermaid 图（无标注） |
| `work/mermaid-metadata.json` | Mermaid 节点元数据 |
| `work/mermaid-final.md` | 标注后的 Mermaid 图（已合并到 Markdown 报告末尾） |
| `work/validation.json` | 报告结构验证结果 |

## 发现概览

本次评审共产出 23 个发现：17 个由脚本确定性生成，6 个由 LLM 分析产出。

| 严重程度 | 数量 | 来源 |
|---------|------|------|
| 🔴 Critical | 2 | 脚本 2 |
| 🟡 Medium | 11 | 脚本 7 + LLM 4 |
| 🟢 Low | 7 | 脚本 6 + LLM 1 |
| 🔵 Awareness | 3 | 脚本 2 + LLM 1 |

LLM 分析的是需要判断力的检查项：Bot Control 策略、Cookie 逻辑、Always-on Challenge 的覆盖范围、PCI DSS、跨规则的修复影响。自审时又补了一条限速覆盖的发现。另有 5 条需要业务背景才能定级，标记为 ⏳。
