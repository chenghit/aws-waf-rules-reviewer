# AWS WAF 规则评审工具

[English](README_EN.md)

一个用于评审 AWS WAF Web ACL 配置的 [Agent Skill](https://agentskills.io)，帮助发现安全问题、配置错误和优化机会。

## 功能

给定一个 AWS WAF Web ACL 的 JSON 导出文件，该 skill 会：

1. 构建规则执行流 — 梳理每条规则的优先级、动作、标签和依赖关系
2. 按 18 项检查清单逐项审查，覆盖 Allow 规则审计、scope-down 验证、AntiDDoS AMR 配置、Bot Control 设置、SEO 影响、速率限制、跨规则依赖等
3. 生成按严重程度分级的评审报告（Critical / Medium / Low / Awareness）
4. 在附录中包含 Mermaid 流程图和逐条规则的执行流详情
5. 自审报告，查找检查清单可能遗漏的问题

## 安装

将 `aws-waf-rules-reviewer` 目录（包含 `SKILL.md` 和 `references/`）复制到你的 AI 编程工具的 skill 目录。例如在 Kiro CLI 中：

```
~/.kiro/skills/aws-waf-rules-reviewer/
├── SKILL.md
└── references/
    ├── checklist.md
    └── waf-knowledge.md
```

然后在你的 agent 配置中加载该 skill，具体方式请参考你所使用工具的文档。

## 输入

AWS WAF Web ACL 的 JSON 格式配置文件，通常通过以下方式获取：

- 从 AWS 控制台导出（Web ACL → "Download web ACL as JSON"）
- 使用 AWS CLI：`aws wafv2 get-web-acl --name <name> --scope <REGIONAL|CLOUDFRONT> --id <id>`

可以提供 JSON 文件的直接路径，也可以提供包含 JSON 文件的目录路径。

## 输出

一份 Markdown 格式的评审报告（`waf-review-report.md`），包含：

- **摘要表** — 所有发现的问题及其严重程度和影响一览
- **详细发现** — 每个问题对应的规则、当前配置、问题描述和修复建议
- **待用户确认项** — 需要业务上下文才能判断严重程度的发现，标记为 ⏳
- **附录：规则执行流** — Mermaid 流程图提供可视化概览，加上逐条规则的详细列表，展示优先级、动作、标签生产/消费关系和依赖

### 严重程度

| 等级 | 含义 |
|------|------|
| 🔴 Critical | 攻击者可以完全绕过防护，或核心防护机制被禁用 |
| 🟡 Medium | 存在防护缺口，但需要特定条件才能利用 |
| 🟢 Low | 配置不够优化，但不直接影响安全性 |
| 🔵 Awareness | 非漏洞 — 用户应了解的运维信息 |

## 检查清单覆盖范围

评审涵盖 18 个类别，分为两个阶段：

**Phase 1: 独立检查**

1. Allow 规则审计（可伪造性、绕过风险）
2. Scope-down 语句（过窄 / 过宽）
3. AntiDDoS AMR 配置（ChallengeAllDuringEvent、豁免正则、SEO 影响、双实例模式）
4. Challenge 动作适用性（POST/API/原生 App 限制、Count 规则切换风险）
5. Bot Control 配置（Allow 覆盖风险、verified vs unverified bot）
6. 速率规则（激活延迟、阈值合理性、重叠 scope-down）
7. IP 信誉和匿名 IP 规则
8. Landing Page 和 Cookie 逻辑
9. 缺失的基线防护（CRS、KnownBadInputs）
10. WCU 容量感知
11. Token Domain 配置
12. 托管规则组版本
13. 日志和监控
14. byte_match_statement 中的哈希/不透明 search_string
15. Default Action（冗余的尾部 Allow-all 规则检测）
16. HTML 页面 Always-on Challenge（主动 DDoS 防御、免疫时间、爬虫排除）

**Phase 2: 全局交叉检查**

17. 跨规则和标签依赖分析（标签来源核实 + 修复影响分析）
18. 规则优先级排序（标签生产者在消费者之前）

## 版本历史

### v0.2 (2026-03-24)

检查清单从 20 项重组为 18 项（两个阶段）。旧编号到新编号的映射：

| 旧编号 | 新编号 | 变更说明 |
|--------|--------|----------|
| 1–5 | 1–5 | 不变 |
| 6 | 17a | 合并进 Phase 2 "跨规则和标签依赖分析" |
| 7 | 6 | 重编号 |
| 8 | 7 | 重编号 |
| 9 | 17b | 合并进 Phase 2 "跨规则和标签依赖分析" |
| 10 | — | 合并进 section 3（AntiDDoS AMR 配置） |
| 11 | 8 | 重编号 |
| 12 | 18 | 移至 Phase 2 "规则优先级排序" |
| 13–19 | 9–15 | 重编号 |
| 20 | 16 | 重编号 |

### v0.1

初始版本。

## 免责声明

本工具由 AI 驱动，可能产生不准确或不完整的发现。生成的报告旨在作为人工评审的起点，而非替代。在根据报告做出任何变更之前，请务必结合实际 WAF 配置和业务上下文进行验证。
