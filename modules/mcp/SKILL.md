---
name: mcp
description: 将本骨架生成的技能暴露为 Model Context Protocol (MCP) 服务器，供任意 MCP 客户端按工具调用。Use when 需要把技能接入 Claude/Cursor/IDE 等 MCP 生态、或以标准化工具协议对外提供能力时加载。
version: 0.1.0
lgd:
  gates: [G1, G3, G4, G5, G6, G7, G8, G9, G10, G16, G15, G12]
  fail-closed: true
---

# MCP 协议适配（受控子骨架）

## 触发条件
当任务要求把技能接入 **MCP 生态**（Claude Desktop、Cursor、VS Code、任意 MCP client）并以标准化工具协议对外提供能力时加载。

## 协议要点（先读官方规范）
- MCP 传输：stdio / Streamable HTTP / SSE。工具以 `tools/list` + `tools/call` 暴露。
- **认证（G7 强制）**：HTTP 传输必须带 Bearer/API token；本骨架不内置密钥——凭据走环境变量或本地保险库（G3）。
- **签名 Agent Card（呼应 A2A）**：对外暴露的技能建议附带 `agent-card.json`（ed25519/PKI 签名），供调用方校验来源与完整性。

## 步骤
1. 在 `scripts/` 实现 MCP server（推荐官方 `mcp` SDK 或 stdlib-only 的 JSON-RPC over stdio）。
2. 工具 schema 显式声明输入/输出契约与最小权限范围（G5：不得声明"任意/无限制"能力）。
3. 所有外部/工具调用带认证声明；不硬编码 token（G3）。
4. 用 `python gates/gates.py modules/mcp` 跑门禁，全 PASSED 后方可登记 `index.json`。

## 已知陷阱
- 禁止 eval/exec 未受信输入（G4）；禁止把客户端传入参数直接拼入命令（G8）。
- 禁止路径穿越（G15）；读写限定在技能目录内。
- 网关侧工具投毒/隐藏指令检测建议配合 Microsoft AGT 的 MCP Security Gateway（运行时层）。

## 验证
- `python gates/gates.py modules/mcp` → RESULT: PASSED。
- 运行 `python scaffold.py --verify modules/mcp` 复核 digest 一致。
