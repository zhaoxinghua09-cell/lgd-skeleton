# AGENTS.md — LGD 母骨架（microkernel + 文件系统注册表）

> 本文件是 AI 编程 Agent 与本仓库交互的**唯一指令真源**（遵循 Anthropic/OpenAI AGENTS.md 范式，控制在 200 行内，避免上下文膨胀与遵循率下降）。人类贡献者见 README.md 的"参与"一节。

## 这是什么
LGD 母骨架是一套 **Agent 无关、零依赖、fail-closed** 的开源技能/工具骨架：说想法即生成骨架、自动跑安全门禁、可选模块按需加载（套娃）。差异化护城河＝内建 13 道 fail-closed 门禁（覆盖 OWASP Agentic Top 10 2026 build-time）＋伦理护栏（完整 G1–G17 企业级 taxonomy 见 OWASP-COMPLIANCE.md）。

## AI 贡献者硬规则（门禁钩子，不可跳过）
1. **任何对 `modules/` 的改动必须先跑门禁**：`python gates/gates.py <module_dir>`（或 `node --experimental-strip-types gates/gates.ts <module_dir>`）。FAILED 不得提交。
2. **新增模块用脚手架**：`python scaffold.py "想法"` 生成骨架＋自动门禁；不要手写绕过。
3. **禁止硬编码密钥（G3）**：密钥走环境变量/本地保险库，绝不入仓库。
4. **禁止 eval/exec 未受信输入（G4）**：用户输入先校验再使用。
5. **禁止路径穿越（G15）**：文件操作限制在技能目录内；不得覆写 `gates/` `.well-known/` `scaffold.py` `AGENTS.md` `llms.txt`。
6. **伦理红线（G16）**：模块不得声明认证绕过/数据窃取/钓鱼/未获授权访问等意图；逆向与克隆类模块仅限自有或已授权目标。
7. **完整性（G12）**：发布即算 SHA-256 digest，登记进 `.well-known/agent-skills/index.json`，加载前校验。
8. **OWASP Agentic Top 10 (2026) build-time 扩展门禁**：G5 最小权限（ASI-02）/ G6 记忆投毒（ASI-06）/ G7 Agent 间认证（ASI-07）/ G8 输出处理（ASI-05）/ G9 人-Agent 监督（ASI-09）/ G10 流氓 Agent kill-switch（ASI-10）。各门默认 PASSED，仅"危险信号 + 缺声明"才 FAILED，避免误伤干净模块。详见 OWASP-COMPLIANCE.md。

## 模块加载约定（套娃）
- 每个模块是子骨架：`modules/<name>/SKILL.md` + `scripts/`。
- L1 元数据(~100tok) 常驻；命中才加载 L2 指令(<5k)；仅当步骤需要才读 L3 资源。
- 模块内需要子能力时递归加载对应子骨架（套娃）。

## 文化（九声 / LGD）
- **实证优先**：任何声称必须有可复算证据（no proof, no done）。
- **不一致必浮现**：门禁失败即 FAILED，绝不谎报通过（fail-closed）。
- **零丢失蒸馏**：改动先落盘、可复核，单一真源。
- **独立复核**：不可逆动作与发布须经独立复核席（R5），不自我放行。
