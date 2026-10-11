---
name: pdf
description: PDF 表单自动填充与处理工具。Use when 用户需要填表、合并、拆分或提取 PDF 表单内容时加载。
version: 0.1.0
lgd:
  gates: [G1, G3, G4, G5, G6, G7, G8, G9, G10, G16, G15, G12]
  fail-closed: true
---

# PDF 工具（子骨架）

## 触发条件
当任务涉及 PDF（填表、合并、拆分、抽取文本/表单）时加载。

## 步骤
1. 明确输入 PDF 与输出契约（字段映射 / 输出路径）。
2. 优先复用既有 PDF 库，保持 stdlib-only 之外的依赖最小化。
3. 处理含敏感字段的表单时，输出不落明文密钥（G3）。

## 已知陷阱
- 禁止 eval/exec 未受信输入（G4）。
- 禁止路径穿越（G15）；读写限定在技能目录内。

## 验证
- 在仓库根目录运行：`python gates/gates.py modules/pdf`，全部门禁 PASSED。
