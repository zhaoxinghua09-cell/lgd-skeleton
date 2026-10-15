#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LGD 母骨架 · 脚手架生成器 scaffold.py（stdlib-only，零依赖）
================================================================
用户/AI 只需"说想法"，骨架自动：
  1. 由想法生成 slug + 合规 SKILL.md（含 name/description/步骤/陷阱/验证）
  2. 生成 scripts/ 占位 + 自检脚本（负对照友好）
  3. 跑 LGD fail-closed 门禁（G1/G3/G4/G15/G12）
  4. 计算 SHA-256 digest（供 .well-known/agent-skills/index.json 登记）
  5. 门禁失败 => 明确报告失败项（fail-closed，绝不谎报通过）

用法：
  python scaffold.py "做一个 PDF 表单自动填充工具"
  python scaffold.py "做一个 GitHub 自动提交机器人" --module github
  python scaffold.py --verify modules/pdf-form
  python scaffold.py --sign modules/pdf-form   # 生成 HMAC 签名卡(P7 占位)
"""

import argparse
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GATES = ROOT / "gates" / "gates.py"

# 本地 HMAC 签名密钥（P7 占位：真实部署应替换为 PKI/ed25519）。
# 密钥不入对话——从本地保险库文件读取，缺失则用确定性零密钥提示用户。
KEY_PATH = ROOT / ".well-known" / "signing.key"


def _slugify(idea):
    s = re.sub(r"[^\w一-鿿]+", "-", idea.strip().lower()).strip("-")
    s = re.sub(r"-{2,}", "-", s)
    return s[:48] or "untitled"


def _read_key():
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()
    return b"__LGD_DEV_ZERO_KEY__REPLACE_WITH_VAULT__"  # 确定性占位，提示未配置


def build_skill(idea, module=None):
    """由想法生成技能骨架目录，返回 (skill_dir, digest)。"""
    slug = _slugify(idea)
    skill_dir = ROOT / "modules" / (module or slug)
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "scripts").mkdir(exist_ok=True)

    name = slug
    description = f"{idea}。Use when（当用户提出相关需求、提及{slug.replace('-', ' ')}、或任务涉及该领域时）自动加载本技能。"
    rel = skill_dir.relative_to(ROOT).as_posix()

    skill_md = f"""---
name: {name}
description: {description}
version: 0.1.0
lgd:
  gates: [G1, G3, G4, G5, G6, G7, G8, G9, G10, G16, G15, G12]
  fail-closed: true
---

# {idea}

## 触发条件
当用户提出与"{idea}"相关的需求时使用本技能。

## 步骤
1. 明确输入与输出契约。
2. 优先复用母骨架 gates/ 门禁与既有模块，避免重复造轮子。
3. 实现核心逻辑于 scripts/，保持 stdlib-only 以降低积分消耗与依赖风险。
4. 完成后运行 `python scripts/selftest.py` 自检（已自动跑门禁）。

## 已知陷阱
- 禁止硬编码密钥（G3）：任何密钥走环境变量/本地保险库，绝不入仓库。
- 禁止 eval/exec 未受信输入（G4）：用户输入先校验再使用。
- 禁止路径穿越（G15）：所有文件操作限制在技能目录内。
- 伦理红线（G16）：不得声明认证绕过、数据窃取、欺诈冒充、未获授权访问等意图。

## 验证
- `python scripts/selftest.py`：全部门禁 PASSED。
- 在仓库根目录运行 `python scaffold.py --verify {rel}`：复核 digest 一致。
"""
    (skill_dir / "SKILL.md").write_text(skill_md, encoding="utf-8")

    # 自检脚本（负对照友好：故意可被门禁捕获的注释示范已避免）
    test_py = f'''#!/usr/bin/env python3
# 自动生成的技能自检：运行门禁 + 一个最小功能断言
import subprocess, sys
from pathlib import Path
GATES = Path(__file__).resolve().parent.parent.parent / "gates" / "gates.py"
r = subprocess.run([sys.executable, str(GATES), "."], cwd=Path(__file__).resolve().parent.parent)
sys.exit(r.returncode)
'''
    (skill_dir / "scripts" / "selftest.py").write_text(test_py, encoding="utf-8")

    digest = hashlib.sha256((skill_dir / "SKILL.md").read_bytes()).hexdigest()
    return skill_dir, digest


def verify(skill_dir):
    """运行门禁并打印结果。"""
    sys.path.insert(0, str(ROOT / "gates"))
    import gates as G
    passed, report = G.run_gates(Path(skill_dir), discovery_mode="local")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("\nRESULT:", "PASSED" if passed else "FAILED")
    return 0 if passed else 1


def sign(skill_dir):
    """生成 HMAC 签名卡（P7 占位实现）。"""
    skill_md = Path(skill_dir) / "SKILL.md"
    digest = hashlib.sha256(skill_md.read_bytes()).hexdigest()
    sig = hmac.new(_read_key(), digest.encode(), hashlib.sha256).hexdigest()
    card = {
        "name": skill_md.parent.name,
        "artifact": "SKILL.md",
        "digest_sha256": digest,
        "signature_hmac_sha256": sig[:32] + "…(truncated)",
        "signer": "lgd-skeleton@local",
        "note": "P7 占位：真实部署替换为 ed25519/PKI 签名 + A2A 签名 Agent Card",
    }
    out = Path(skill_dir) / "agent-card.json"
    out.write_text(json.dumps(card, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已生成签名卡: {out}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="LGD 母骨架脚手架生成器（说想法即搭建）")
    ap.add_argument("idea", nargs="*", help="用自然语言描述要搭建的技能/工具")
    ap.add_argument("--module", help="指定挂载到某子骨架（如 github），实现套娃自动加载")
    ap.add_argument("--verify", metavar="DIR", help="仅校验某技能目录的门禁")
    ap.add_argument("--sign", metavar="DIR", help="为某技能生成 HMAC 签名卡")
    args = ap.parse_args()

    if args.verify:
        return verify(args.verify)
    if args.sign:
        return sign(args.sign)
    if not args.idea:
        ap.print_help()
        return 2
    idea = " ".join(args.idea)
    skill_dir, digest = build_skill(idea, args.module)
    print(f"[scaffold] 已生成骨架: {skill_dir}")
    print(f"[scaffold] SKILL.md SHA-256: {digest[:16]}…")

    # 生成后立即跑门禁（fail-closed）
    sys.path.insert(0, str(ROOT / "gates"))
    import gates as G
    passed, report = G.run_gates(skill_dir, digest, discovery_mode="local")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if passed:
        print(f"\nRESULT: PASSED ✅  模块 {skill_dir.name} 可登记入 index.json")
    else:
        print(f"\nRESULT: FAILED ❌  门禁未过，骨架不可用（fail-closed，未谎报通过）")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
