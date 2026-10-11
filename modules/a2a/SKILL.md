---
name: a2a
description: 将本骨架生成的技能作为 Agent-to-Agent (A2A) 可互操作智能体，携带签名身份（Agent Card）与其他 Agent 安全协作。Use when 需要让技能以标准化智能体身份接入多 Agent 网格、或与其他智能体做可信消息传递时加载。
version: 0.1.0
lgd:
  gates: [G1, G3, G4, G5, G6, G7, G8, G9, G10, G16, G15, G12]
  fail-closed: true
---

# A2A 协议适配（受控子骨架）

## 触发条件
当任务要求技能以 **A2A 协议**（Agent-to-Agent，Google/行业草案）参与多 Agent 协作、携带身份与其他智能体通信时加载。

## 协议要点（先读官方规范）
- A2A 以 **Agent Card**（JSON，含 skill 清单 + 认证方案 + 端点）做服务发现与信任锚。
- **认证（G7 强制）**：Agent Card 必须声明 authSchemes（OAuth2/API key/mTLS）；调用须带签名身份。
- **信任门**：跨 Agent 消息建议经 Ed25519/SPIFFE 风格签名与信任评分（呼应 AGT AgentMesh），母骨架仅提供声明级要求，运行时信任由平台/AGT 提供。

## 步骤
1. 生成 `agent-card.json`：name、description、skills、authSchemes、端点；并用 ed25519/PKI 签名（可复用 `scaffold.py --sign` 占位）。
2. 消息收发走声明式 auth；不硬编码凭据（G3）。
3. 明确本 Agent 的最小权限范围（G5：不宣称"任意/无限制"能力）。
4. `python gates/gates.py modules/a2a` 全 PASSED 后登记 `index.json`。

## 已知陷阱
- 禁止 eval/exec 未受信输入（G4）；禁止把对端消息直接拼入命令（G8）。
- 禁止路径穿越（G15）。
- 跨 Agent 信任投毒/未授权通信建议配合 AGT AgentMesh（运行时层）。

## 验证
- `python gates/gates.py modules/a2a` → RESULT: PASSED。
- `python scaffold.py --verify modules/a2a` 复核 digest 一致。
