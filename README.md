# LGD 母骨架 · lgd-skeleton

> **Agent 无关 · 零依赖 · fail-closed 的开源技能/工具骨架** —— 让个人零门槛"说想法即搭建"，让企业用 Git-native 统一治理团队 AI，让 AI 自己能发现并参与。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Gates: fail-closed](https://img.shields.io/badge/gates-fail--closed-green.svg)](gates/gates.py)
[![Tests: negative-controls passing](https://img.shields.io/badge/tests-negative--controls%20passing-brightgreen.svg)](scaffold_test.py)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](VERSION)

## 为什么是它（差异化）

通用脚手架（bolt / v0 / Lovable）能"说想法即生成"，但**安全是行业公认缺口**（OWASP、OWASP Agentic Top 10 报告均指出 vibe-coding 产出的安全隐患）。LGD 母骨架把 **13 道 fail-closed 门禁（映射 OWASP Agentic Top 10 2026 build-time）＋伦理护栏**内建进生成骨架——这是与通用工具拉开身位的抓手。⚠️ **注意**：本骨架门禁为 build-time 的 naive-pattern 启发式，**不构成安全边界**，存在已文档化的绕过面；运行时隔离须配合 AGT/容器，见 OWASP-COMPLIANCE.md 与 SECURITY.md。

| 维度 | 通用脚手架 | 团队分发(teamAI) | 逆向(REA) | 克隆站 | **LGD 母骨架** |
|------|-----------|-----------------|-----------|--------|----------------|
| 说想法即生成 | ✅ | ❌ | ❌ | ❌ | ✅ |
| 安全门禁内建 | ❌ | ❌ | ❌ | ⚠️ | ✅ |
| 完整性可验证 | ❌ | ⚠️ | ❌ | ❌ | ✅ |
| 伦理护栏 | ❌ | ❌ | ⚠️ | ⚠️ | ✅ |
| 零依赖/可移植 | ❌ | ❌ | ⚠️ | ❌ | ✅ |
| Agent 无关 | ❌ | ⚠️ | ✅ | ⚠️ | ✅ |
| OWASP Agentic Top10(2026) build-time | ❌ | ❌ | ❌ | ❌ | ✅ |

## 对个人：零门槛上手

```bash
# 1. 说想法即生成技能骨架（自动跑门禁 + 算 digest）
python scaffold.py "做一个 PDF 表单自动填充工具"

# 2. 校验任意模块
python scaffold.py --verify modules/pdf

# 3. 生成签名卡（完整性 + 溯源）
python scaffold.py --sign modules/pdf

# 4. 用 TypeScript 端口校验（无需 Python 环境）
node --experimental-strip-types gates/gates.ts modules/pdf
```

生成的骨架默认过 LGD 门禁，密钥不硬编码、无路径穿越、无注入、带 SHA-256 完整性校验。双端口共享同一套正则 / 熵 / realpath 语义；Python 端口 `gates/gates.py` 另加 AST 级检测，对 TypeScript 端口 `gates/gates.ts` 构成**保守超集**——凡 TS 能拦的，Python 一定也能拦（反之不成立，已文档化）。

## 对企业：Git-native 团队治理

借鉴 Tencent teamAI 思路（push → review & merge → pull），把 `modules/` 当作版本化、可 MR 审查的团队 AI 资产：
- 成员 `scaffold.py` 生成候选 → 开 MR → reviewer 合并 → 他人下次会话自动 pull。
- `AGENTS.md` 内嵌门禁钩子，AI 贡献者无法跳过门禁。
- 九声文化 + LGD 门禁作为团队"宪法"注入每个 Agent。

## 让 AI 也能发现并参与（AI-native 分发）

- `llms.txt`：站点/内容索引，供 AI 检索与引用。
- `.well-known/agent-skills/index.json`：机器可发现清单，每模块带 `type/url/digest`，加载前必校验完整性。
- 遵循 Cloudflare Agent Skills Discovery RFC v0.2.0 的扁平单 artifact 模型。
- `OWASP-COMPLIANCE.md`：诚实声明 build-time 13 道门禁对 ASI-01..10 的映射，以及运行时项（沙箱/权限环/kill-switch）须配合 AGT/容器。

## 参与

- **个人贡献**：用 `scaffold.py` 生成模块 → 跑门禁 → 提 MR。门槛近零。
- **企业接入**：Fork → 团队 `modules/` 治理 → SessionStart 同步。
- 规则详见 `AGENTS.md`（AI 贡献者）与本文件。

## 已知局限（诚实范围）

- 本骨架的 13 道门禁是 **build-time 的 regex / 熵 / AST 启发式**，**不构成安全边界**。独立红队实测（2026-10-11，M8 加固后复跑）测得 **26 个主动绕过探针中仍有 18 类可绕过**（混淆 / 同义 / 伪声明 / 替代 API），另 **8/8 对照被正确拦截、安全样本 0 误伤**（详见 `SECURITY.md` 的 *Known bypass surface* 与 `OWASP-COMPLIANCE.md`）。
- **M8 加固（2026-10-11）已把多类原本漏过的构造升级为可检测**：G3 高熵密钥（熵 ≥ 4.5 bit/char）、G4 `os.popen` / `__import__`、G15 `..%2f` 与 `..\..\` 穿越、G10 `while 1` 等；全角 `ｅｖａｌ` 由 Python 端口额外拦下。剩余仍诚实声明为未覆盖。
- 门禁的真正价值在于：**确定性拦截明显违规**（坏输入必 FAIL，34 道负对照 + 6 道正对照/不误伤守卫 + fail-closed 场景，双端口各 40 项全绿）与**强制诚实声明**（scope / 认证 / kill-switch 须显式写出），作为进仓库前的**第一道低门槛过滤网**，而非运行时防护。
- **真实运行时安全**须叠加 Microsoft Agent Governance Toolkit（AGT）或每-Agent 容器隔离；本骨架不提供沙箱、权限环、强制 kill-switch 或零信任身份。

## 状态

- 门禁经双端口负对照测试（Python + TypeScript 各 34 类负对照必 FAIL + 6 类正对照/不误伤守卫 + 正对照全过 + fail-closed 异常不默认放行，各 40 项全绿），见 `scaffold_test.py` 与 `gates/gates.test.ts`。
- 许可：MIT。
