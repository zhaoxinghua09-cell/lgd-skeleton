---
name: clone-site
description: 把自有或已获授权的网站重建为可维护的 Next.js 代码库。Use when 需要迁移遗留站点、恢复丢失源码、或学习某站点的布局实现、且你拥有或已获授权时加载。
version: 0.1.0
lgd:
  gates: [G1, G3, G4, G5, G6, G7, G8, G9, G10, G16, G15, G12]
  fail-closed: true
---

# 网站克隆（受控子骨架）

## 触发条件
当用户提出"克隆 / 重建某网站"，且目标为**自有站点 / 已授权迁移 / 失源恢复**时加载本技能。

## 五阶段流水线（吸收 ai-website-cloner-template）
1. **侦察**：多断点截图 + `getComputedStyle()` 扫全可见元素 + 交互扫描（滚动/点击/hover/响应式）。
2. **搭基**：更新 `globals.css`（OKLCH token）、装字体、下载静态资源到 `public/`。
3. **组件规格**：每 section 一份 spec，含精确 computed CSS 值、交互态、内容、资产路径、断点。
4. **并行构建**：git worktree 并行派 builder Agent，一个组件一个。
5. **装配与 QA**：合并 worktree → 视觉 diff 原站 → 输出 `comparison.png`。

## 权属与合规（G16 前置，Phase 0）
- 仅克隆**自有站点 / 已授权迁移 / 失源恢复**。
- 不得用于冒充他人站点或欺诈；不得违反目标站点的服务条款。
- 下载的字体 / 图片须确认可复用；门禁保留 G3 秘密扫描。

## 步骤
1. 确认目标权属与用途（Phase 0 门禁），未通过则整轮 fail-closed。
2. 按五阶段流水线执行。
3. 产物须标注来源与授权状态。

## 验证
- 在仓库根目录运行：`python gates/gates.py modules/clone-site`，全部门禁 PASSED。
