# LGD 母骨架 · OWASP Agentic Top 10 (2026) 合规映射

> 目标：诚实声明母骨架对 **OWASP Agentic AI Top 10 (2026)** 的覆盖方式与边界。
> 对标基准：Microsoft Agent Governance Toolkit (AGT) 是覆盖面最广的 Agent 治理开源工具（其官方口径为 10 项 ASI 中 **7 项 full + 3 项 partial** + 运行时治理）；本骨架是 **build-time（构建/贡献时）门禁**，两者层级不同，不互相替代。（"首个""10/10 全覆盖" 为 AGT 自身营销口径，本骨架不独立佐证。）

## 一、能力分层（先说清"在哪一层"）

| 层 | 谁负责 | 母骨架是否覆盖 |
|----|--------|----------------|
| 构建/贡献时（技能编写） | **LGD 母骨架 gates** | ✅ 本文件主体 |
| 运行时（Agent 部署后） | AGT / 容器 / 权限环 | ⚠️ 须配合，母骨架不内置 |

**核心判据**：母骨架的 `gates.py` 是**静态、build-time** 检查器——它在技能被提交/加载前扫描源码与声明。它**不能**在 Agent 运行时拦截越权调用、不能提供进程隔离。运行时安全必须叠加 AGT 或每-Agent 容器。

## 二、10/10 映射表（ASI-01 ～ ASI-10）

| ASI | 风险 | 母骨架 build-time 覆盖 | 门禁 | 覆盖性质 |
|-----|------|----------------------|------|----------|
| ASI-01 目标劫持 (Goal Hijacking) | 指令注入改写目标 | ✅ | **G4** 注入扫描（eval/exec/os.system/shell=True/HTML 注入） | 可检 |
| ASI-02 过度能力 (Excessive Capabilities) | 最小权限被突破 | ✅ | **G5** 过度宽泛能力声明须配 scope | 可检 |
| ASI-03 身份/权限滥用 (Identity Abuse) | 凭据泄露/提权 | ✅ | **G3** 秘密扫描（硬编码密钥/JWT/service_role） | 可检 |
| ASI-04 失控代码执行 (Uncontrolled Code Exec) | 任意代码跑 | ✅ | **G4** + **G8** 未受信输入拼入命令 | 可检 |
| ASI-05 不安全输出处理 (Insecure Output Handling) | 输出被当指令/命令 | ✅ | **G8** 输出插值校验 | 可检 |
| ASI-06 记忆投毒 (Memory Poisoning) | 外部内容污染记忆 | ✅ | **G6** 记忆文件外部内容须带来源 | 可检 |
| ASI-07 不安全 Agent 间通信 (Unsafe Inter-Agent Comm) | 未授权 Agent 互调 | ✅ | **G7** Agent 互调/MCP/A2A 暴露须配认证 | 可检 |
| ASI-08 级联故障 (Cascading Failures) | 单点故障扩散 | ⚠️ | **结构性警告**（见下）+ 建议 AGT 熔断 | 部分 |
| ASI-09 人-Agent 信任缺口 (Human-Agent Trust) | 不可逆动作无监督 | ✅ | **G9** 高风险动作须配 human-in-the-loop 声明 | 可检 |
| ASI-10 流氓 Agent (Rogue Agents) | 失控自治循环 | ✅ | **G10** 自治/循环须配 kill-switch 声明 | 可检 |

> **结论**：10 项中 **9 项有确定可检的 build-time 门禁**；**ASI-08（级联故障）仅作结构性警告，无 build-time gate**（建议配 AGT 熔断），故准确口径为「9 项 gate 覆盖 + 1 项警告」。与通用脚手架的差别在于本骨架至少有显式门禁，但**相对安全性未经独立基准测评**，不声称优于任何具体产品（见 `SECURITY.md` 已知绕过面）。

## 三、诚实边界（哪些我们不做，必须配合外部）

| 维度 | AGT 已做 | 母骨架**不做**（诚实声明） | 建议 |
|------|----------|--------------------------|------|
| 运行时权限环 | 4 级 privilege rings | ❌ | 部署每 Agent 独立容器 / 接 AGT runtime |
| 沙箱 / kill switch（运行时） | ✅ saga + kill switch | ❌（仅 build-time 声明要求） | 运行时 kill switch 由平台提供 |
| 零信任身份 (Ed25519/SPIFFE) | ✅ | ⚠️ 仅要求声明，不签发 | mcp/a2a 模块给出签名 Agent Card 模板 |
| MCP 安全网关 / 工具投毒检测 | ✅ | ⚠️ 仅要求认证声明 | 接 AGT MCP Security Gateway |
| Merkle 审计 / 合规证据导出 | ✅ | ❌（digest 防篡改仅覆盖 SKILL.md） | 接 AGT Audit / 本骨架 `--sign` 占位 |
| 992 conformance tests | ✅ | ✅ 本骨架 12 + 负对照（规模小） | 持续扩充 |

## 四、与 AGT 的关系（不重复造轮子）

母骨架与 AGT **互补非竞争**：
- **母骨架** = 技能/工具的**编写期**质量门禁 + Agent Skills 范式发现（llms.txt/index.json）。让"坏技能"在进仓库前被拦。
- **AGT** = Agent **运行时**治理中间件（Python/TS/.NET/Rust/Go，14–20+ 框架适配器）。

推荐组合：母骨架做 build-time 门禁 → AGT 做 runtime 治理 → 容器做 OS 级隔离。两者通过 `modules/mcp`、`modules/a2a` 的签名 Agent Card 衔接。

## 五、验证

- build-time 门禁全套负对照：`python scaffold_test.py`（12 项负对照 + 正对照 + fail-closed，全过）。
- 单模块核验：`python gates/gates.py modules/<name>`，期望 RESULT: PASSED。
- digest 防篡改：`index.json` 中每模块 `digest` 须与 `python -c "import hashlib,pathlib;print(hashlib.sha256(pathlib.Path('modules/<name>/SKILL.md').read_bytes()).hexdigest())"` 一致。

---
*来源：OWASP Agentic AI Top 10 for 2026（genai.owasp.org）；Microsoft AGT 官方 README（github.com/microsoft/agent-governance-toolkit），2026-10-11 检索。*
