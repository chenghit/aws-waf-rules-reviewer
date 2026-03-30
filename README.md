# AWS WAF 规则评审工具

[English](README_EN.md)

一个用于评审 AWS WAF Web ACL 配置的 [Agent Skill](https://agentskills.io)，帮助发现安全问题、配置错误和优化机会。

## 工作流程

```mermaid
flowchart LR
    A["WAF JSON"] --> B["预处理"]
    B --> C["Mermaid 图生成"]
    B --> D["机械预检"]
    C --> E["LLM 分析"]
    D --> E
    E --> F["Mermaid 标注"]
    F --> G["报告验证"]
    G --> H["LLM 自审"]
    H --> I["评审报告"]

    style B fill:#e1f5fe
    style C fill:#e1f5fe
    style D fill:#e1f5fe
    style F fill:#e1f5fe
    style G fill:#e1f5fe
    style E fill:#fff3e0
    style H fill:#fff3e0
```

蓝色 = Python 脚本（确定性），橙色 = LLM 推理

脚本处理结构化提取、图表生成和机械验证，LLM 聚焦于安全分析和报告撰写。如果脚本未安装，自动回退到纯 LLM 工作流。

## 功能

给定一个 AWS WAF Web ACL 的 JSON 导出文件，该 skill 会：

1. **预处理** — 提取结构化规则摘要，压缩输入（56KB → 16KB）
2. **机械预检** — 自动检测 token domain 冗余、版本过旧、冗余规则等 5 项确定性问题
3. **LLM 分析** — 按 18 项检查清单逐项审查，覆盖 Allow 规则审计、scope-down 验证、AntiDDoS AMR 配置、Bot Control 设置、SEO 影响、速率限制、跨规则依赖等
4. **报告生成** — 按严重程度分级的评审报告（Critical / Medium / Low / Awareness）
5. **Mermaid 流程图** — 自动生成规则执行流程图，标注问题引用
6. **自审** — 机械验证 + 对抗性检查，确保报告准确性

## 安装

将 `aws-waf-rules-reviewer` 目录复制到你的 AI 编程工具的 skill 目录。例如在 Kiro CLI 中：

```bash
./install.sh
```

安装后的目录结构：

```
~/.kiro/skills/aws-waf-rules-reviewer/
├── SKILL.md
├── references/
│   ├── checklist.md
│   └── waf-knowledge.md
└── scripts/
    ├── managed-labels.json
    ├── waf-preprocess.py
    ├── waf-generate-mermaid.py
    ├── waf-pre-checks.py
    ├── waf-annotate-mermaid.py
    └── waf-validate-report.py
```

**依赖**: Python 3.10+（标准库，无需 pip install）

对于其他工具（Claude Code、OpenRouter 等），将目录复制到对应的 skill 目录即可。脚本通过 `glob` 自动发现安装位置，无需配置路径。

## 输入

AWS WAF Web ACL 的 JSON 格式配置文件，通常通过以下方式获取：

- 从 AWS 控制台导出（Web ACL → "Download web ACL as JSON"）
- 使用 AWS CLI：`aws wafv2 get-web-acl --name <name> --scope <REGIONAL|CLOUDFRONT> --id <id>`

可以提供 JSON 文件的直接路径，也可以提供包含 JSON 文件的目录路径。支持三种 JSON 格式：AWS CLI 输出（PascalCase）、控制台导出、snake_case 自定义格式。

## 输出

一份 Markdown 格式的评审报告（`waf-review/waf-review-report.md`），包含：

- **摘要表** — 所有发现的问题及其严重程度和影响一览
- **详细发现** — 每个问题对应的规则、当前配置、问题描述和修复建议
- **待用户确认项** — 需要业务上下文才能判断严重程度的发现，标记为 ⏳
- **附录：规则执行流** — Mermaid 流程图，自动标注问题引用

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

见 [CHANGELOG.md](CHANGELOG.md)。

## 免责声明

本工具由 AI 驱动，可能产生不准确或不完整的发现。生成的报告旨在作为人工评审的起点，而非替代。在根据报告做出任何变更之前，请务必结合实际 WAF 配置和业务上下文进行验证。
