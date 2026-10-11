---
name: github
description: 在已授权仓库上执行 Git/GitHub 操作（提交、建分支、开合并请求、同步）。Use when 任务涉及提交代码、创建分支、开 PR 或同步远程仓库时加载。
version: 0.1.0
lgd:
  gates: [G1, G3, G4, G5, G6, G7, G8, G9, G10, G16, G15, G12]
  fail-closed: true
---

# GitHub 操作（子骨架）

## 触发条件
当任务涉及 Git/GitHub（提交、分支、PR、同步）且你已获仓库写入授权时加载。

## 步骤
1. 确认仓库授权与远端可达。
2. 小步提交，commit 信息清晰描述意图。
3. 开 PR 前确保本技能目录门禁 PASSED。
4. 不可逆动作（force push / 删分支）须经人工确认，不自动执行。

## 已知陷阱
- 禁止在脚本中硬编码 token（G3）；凭据走环境变量或本地保险库。
- 禁止路径穿越（G15）；操作限定在仓库目录内。

## 验证
- 在仓库根目录运行：`python gates/gates.py modules/github`，全部门禁 PASSED。
