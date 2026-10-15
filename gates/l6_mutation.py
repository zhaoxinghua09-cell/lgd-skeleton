#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L6 变异自证：对 G17 的每个承重判据做一次源码变异，证明对应检查确实变红；
还原后证明变绿。不删除任何文件（只覆写 gates.py 并还原原始字节）。"""
import subprocess, sys, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # 本文件位于 <repo>/gates/ 下，父目录即仓库根
GATES = ROOT / "gates" / "gates.py"
TEST = ROOT / "scaffold_test.py"
PY = r"C:/Users/Administrator/.workbuddy/binaries/python/envs/default/Scripts/python.exe"

# (变异名, 目标原文, 变异后, 期望变红的检查标签)
MUTS = [
    ("M1 $schema 白名单失效", "if schema not in KNOWN_SCHEMA_URIS:", "if False:", "G17负对照4"),
    ("M2 digest 正则失效", "if not isinstance(dg, str) or not DIGEST_RE.match(dg):", "if False:", "G17负对照2"),
    ("M3 description 长度失效", "if not isinstance(desc, str) or not (1 <= len(desc) <= 1024):", "if False:", "G17负对照3"),
    ("M4 name 形状/连字符失效", "if not isinstance(nm, str) or not SKILL_NAME_RE.match(nm) or \"--\" in nm:", "if False:", "G17负对照5"),
    ("M5 type 白名单失效", "if ent.get(\"type\") not in DISCOVERY_TYPES:", "if False:", "G17负对照11"),
    ("M6 structural 跳过失效(会去解析 url)", "if mode != \"local\":", "if False:", "G17两模式1"),
    ("M7 模式守卫失效(未指定不再 FAIL)", "if mode not in DISCOVERY_MODES:", "if False:", "G17 fail-closed"),
    ("M8 url->文件存在性失效", "        if not target.is_file():\n            problems.append(f\"{tag}: url 指向文件不存在: {ent.get('url')}\")\n            continue", "        if not target.is_file():\n            continue", "G17负对照9"),
    ("M9 digest 与文件实算比对失效", "if actual != want:", "if False:", "G17负对照1"),
]


def run_test():
    r = subprocess.run([PY, str(TEST)], cwd=str(ROOT), capture_output=True)
    out = (r.stdout + r.stderr).decode("utf-8", "replace")
    return out


def label_status(out, label):
    for line in out.splitlines():
        if label in line and line.startswith("["):
            return "FAIL" if line.startswith("[FAIL]") else "OK"
    return "MISSING"


orig = GATES.read_bytes()
text = orig.decode("utf-8")

print("== 基线（未变异）==")
out = run_test()
base_red = [l for l in out.splitlines() if l.startswith("[FAIL]")]
print("基线 FAIL 行数 =", len(base_red))
print("基线 G17 相关结果:")
for lb in ["G17负对照2", "G17负对照9", "G17两模式1", "G17 fail-closed"]:
    print("   ", lb, "->", label_status(out, lb))

rows = []
for name, old, new, expect in MUTS:
    if old not in text:
        rows.append((name, expect, "ANCHOR-MISSING", "NOT-MUTATED"))
        continue
    mutated = text.replace(old, new, 1)
    assert mutated != text
    GATES.write_bytes(mutated.encode("utf-8"))
    try:
        out2 = run_test()
        st = label_status(out2, expect)
    finally:
        GATES.write_bytes(orig)  # 还原
    # 还原后确认该标签回到 OK
    out3 = run_test()
    st_restored = label_status(out3, expect)
    rows.append((name, expect, st, st_restored))

print("\n== 变异自证表 ==")
print("%-34s %-16s %-10s %-12s" % ("变异", "期望变红的检查", "变异后", "还原后"))
ok_all = True
for name, expect, st, st_r in rows:
    good = (st == "FAIL" and st_r == "OK")
    ok_all = ok_all and good
    print("%-34s %-16s %-10s %-12s %s" % (name, expect, st, st_r, "PASS" if good else "PROBLEM"))

print("\nL6 变异自证:", "全部承重判据均可致红、还原后复原 ✅" if ok_all else "存在未致红判据 ❌")
sys.exit(0 if ok_all else 1)
