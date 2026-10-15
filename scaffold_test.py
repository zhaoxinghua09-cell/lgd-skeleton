#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LGD 母骨架 · 门禁负对照测试（R1 可失败才算门 / R4 附 PROOF）
================================================================
证明：
  - 合规技能 => 全部门禁 PASSED（正对照）
  - 缺失 description => G1 FAILED
  - 含硬编码密钥 => G3 FAILED
  - 含 eval(未受信) => G4 FAILED
  - 含 ../ 穿越 => G15 FAILED
  - digest 不匹配 => G12 FAILED
  - 任一异常 => fail-closed FAILED（不可默认放行）
"""

import contextlib
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# 工作区内、不自动删除的临时目录。
# 背景：环境红线守卫（redline_guard）在"删除含凭据样式文件的目录"时会终止整个进程，
# 而本套件的 G3 负对照必须写入凭据样式内容，故测试不自动清理临时目录；
# `._test_scratch/` 已写入 .gitignore，可安全手动清除。
_SCRATCH = ROOT / "._test_scratch"
_SCRATCH.mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT / "gates"))
import gates as G


def RG(skill_dir, expected_digest=None, repo_root=None, mode="local"):
    """run_gates 包装：显式传入 G17 发现层模式（默认 local=对本地文件实算校验）。
    G17 为 fail-closed：模式缺省即 FAILED，故本套件所有调用均显式给 local。"""
    return G.run_gates(skill_dir, expected_digest, repo_root, mode)

FAILURES = []


@contextlib.contextmanager
def scratch_dir():
    """生成工作区内、不自动删除的临时目录（原因见文件顶部注释）。"""
    _SCRATCH.mkdir(exist_ok=True)
    yield Path(tempfile.mkdtemp(dir=str(_SCRATCH)))


def check(name, cond):
    status = "OK" if cond else "FAIL"
    print(f"[{status}] {name}")
    if not cond:
        FAILURES.append(name)


def write_skill(d, name, desc, body_extra="", scripts=None):
    d = Path(d)
    d.mkdir(parents=True, exist_ok=True)
    fm = f"---\nname: {name}\ndescription: {desc}\n---\n\n# {name}\n{body_extra}\n"
    (d / "SKILL.md").write_text(fm, encoding="utf-8")
    if scripts:
        (d / "scripts").mkdir(exist_ok=True)
        for fn, content in scripts.items():
            (d / "scripts" / fn).write_text(content, encoding="utf-8")


# --- 正对照：合规技能 ---
with scratch_dir() as tmp:
    good = Path(tmp) / "good"
    write_skill(good, "pdf-form", "PDF 表单自动填充工具。Use when 用户需要填表或处理 PDF 表单时加载。",
                scripts={"run.py": "print('ok')\n"})
    passed, rep = RG(good)
    check("正对照: 合规技能全部门禁 PASSED", passed)

# --- 负对照 1：缺失 description ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad1"
    write_skill(bad, "x", "短")
    passed, rep = RG(bad)
    g1 = next(r for r in rep if r["gate"] == "G1-metadata")
    check("负对照1: 缺失/过短 description => G1 FAILED", not passed and g1["status"] == "FAILED")

# --- 负对照 2：硬编码凭据 ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad2"
    # 凭据字面量运行时拼接生成，且用无前缀的通用形态（避免源码出现带前缀凭据 token，
    # 与 TS 端口口径一致；命中 G3 的 api_key/secret 赋值规则）。
    cred = "api_key" + " = " + '"' + "X" * 16 + '"'
    write_skill(bad, "api-tool", "调用外部 API 的工具。Use when 需要请求远程接口时加载。",
                scripts={"run.py": cred + "\n"})
    passed, rep = RG(bad)
    g3 = next(r for r in rep if r["gate"] == "G3-secret-scan")
    check("负对照2: 硬编码凭据 => G3 FAILED", not passed and g3["status"] == "FAILED")

# --- 负对照 3：eval 注入 ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad3"
    write_skill(bad, "eval-tool", "动态执行工具。Use when 需要运行时求值任务时加载。",
                scripts={"run.py": "user_in = input(); eval(user_in)\n"})
    passed, rep = RG(bad)
    g4 = next(r for r in rep if r["gate"] == "G4-injection-scan")
    check("负对照3: eval(未受信输入) => G4 FAILED", not passed and g4["status"] == "FAILED")

# --- 负对照 4：脚本内容含 ../ 路径穿越 ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad4"
    write_skill(bad, "trav", "演示路径穿越。Use when 测试时加载。",
                scripts={"run.py": "with open('../gates/gates.py') as f: exec(f.read())\n"})
    passed, rep = RG(bad)
    g15 = next(r for r in rep if r["gate"] == "G15-path-safety")
    check("负对照4: 脚本内容含 ../ 路径穿越 => G15 FAILED", not passed and g15["status"] == "FAILED")

# --- 负对照 5：digest 不匹配 ---
with scratch_dir() as tmp:
    good = Path(tmp) / "good5"
    write_skill(good, "dig", "摘要校验工具。Use when 需要校验完整性时加载。")
    passed, rep = RG(good, expected_digest="0" * 64)
    g12 = next(r for r in rep if r["gate"] == "G12-digest")
    check("负对照5: digest 不匹配 => G12 FAILED", not passed and g12["status"] == "FAILED")

# --- 负对照 6：伦理红线意图（G16） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad6"
    write_skill(bad, "evil", "工具用于绕过身份认证并窃取用户数据。Use when 需要入侵系统时加载。",
                scripts={"run.py": "print('run')\n"})
    passed, rep = RG(bad)
    g16 = next(r for r in rep if r["gate"] == "G16-ethics")
    check("负对照6: 声明认证绕过/数据窃取 => G16 FAILED", not passed and g16["status"] == "FAILED")

# --- 负对照 7：G5 过度宽泛能力声明缺 scope（ASI-02） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad7"
    write_skill(bad, "fsaccess", "提供完整文件系统访问的工具。Use when 需要批量处理文件时加载。",
                body_extra="本工具提供 full filesystem access 以处理任意文件。\n")
    passed, rep = RG(bad)
    g5 = next(r for r in rep if r["gate"] == "G5-capability")
    check("负对照7: 过度宽泛能力声明缺 scope => G5 FAILED", not passed and g5["status"] == "FAILED")

# --- 负对照 8：G6 记忆文件含外部内容缺来源（ASI-06） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad8"
    write_skill(bad, "memtool", "带记忆持久化的工具。Use when 需要保存状态时加载。")
    (bad / "memory.md").write_text("从 https://example.com/data 抓取的外部配置。\n", encoding="utf-8")
    passed, rep = RG(bad)
    g6 = next(r for r in rep if r["gate"] == "G6-memory-poisoning")
    check("负对照8: 记忆文件含外部内容缺来源 => G6 FAILED", not passed and g6["status"] == "FAILED")

# --- 负对照 9：G7 Agent 互调/MCP 暴露缺认证（ASI-07） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad9"
    write_skill(bad, "expose", "暴露 MCP 服务器的工具。Use when 需要对外提供工具时加载。",
                body_extra="本技能启动 mcp server 供其他 agent 调用。\n")
    passed, rep = RG(bad)
    g7 = next(r for r in rep if r["gate"] == "G7-inter-agent-auth")
    check("负对照9: Agent 互调/MCP 暴露缺认证 => G7 FAILED", not passed and g7["status"] == "FAILED")

# --- 负对照 10：G8 未受信输入拼入命令缺校验（ASI-05） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad10"
    write_skill(bad, "echotool", "回显用户输入的工具。Use when 需要转发输入时加载。",
                scripts={"run.py": 'x = input()\nsubprocess.run(f"echo {x}")\n'})
    passed, rep = RG(bad)
    g8 = next(r for r in rep if r["gate"] == "G8-output-handling")
    check("负对照10: 未受信输入拼入命令缺校验 => G8 FAILED", not passed and g8["status"] == "FAILED")

# --- 负对照 11：G9 高风险动作缺监督声明（ASI-09） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad11"
    write_skill(bad, "pushbot", "自动 force push 并 delete 分支的工具。Use when 需要强制同步时加载。",
                body_extra="本工具自动 force push 到远端并 delete 旧分支。\n")
    passed, rep = RG(bad)
    g9 = next(r for r in rep if r["gate"] == "G9-human-oversight")
    check("负对照11: 高风险动作缺监督声明 => G9 FAILED", not passed and g9["status"] == "FAILED")

# --- 负对照 12：G10 自治循环缺 kill-switch（ASI-10） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad12"
    write_skill(bad, "daemon", "自治循环守护进程。Use when 需要长期运行时加载。",
                body_extra="本工具 while True 运行 autonomous loop 持续轮询。\n")
    passed, rep = RG(bad)
    g10 = next(r for r in rep if r["gate"] == "G10-rogue-killswitch")
    check("负对照12: 自治循环缺 kill-switch => G10 FAILED", not passed and g10["status"] == "FAILED")

# --- 负对照 13：G3 高熵假密钥（绕过前缀规则，熵检测兜底） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad13"
    blob = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz"
    write_skill(bad, "ent", "熵检测工具。Use when 测试时加载。",
                scripts={"run.py": f'SECRET_BLOB = "{blob}"\n'})
    passed, rep = RG(bad)
    g3 = next(r for r in rep if r["gate"] == "G3-secret-scan")
    check("负对照13: 高熵假密钥 => G3 FAILED", not passed and g3["status"] == "FAILED")

# --- 负对照 14：G4 os.popen（M8 扩展） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad14"
    write_skill(bad, "popen", "执行工具。Use when 测试时加载。",
                scripts={"run.py": "import os\nos.popen('ls')\n"})
    passed, rep = RG(bad)
    g4 = next(r for r in rep if r["gate"] == "G4-injection-scan")
    check("负对照14: os.popen => G4 FAILED", not passed and g4["status"] == "FAILED")

# --- 负对照 15：G4 __import__（M8 扩展） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad15"
    write_skill(bad, "imp", "导入工具。Use when 测试时加载。",
                scripts={"run.py": "mod = __import__('os')\n"})
    passed, rep = RG(bad)
    g4 = next(r for r in rep if r["gate"] == "G4-injection-scan")
    check("负对照15: __import__ => G4 FAILED", not passed and g4["status"] == "FAILED")

# --- 负对照 16：G15 反斜杠路径穿越（M8 扩展） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad16"
    write_skill(bad, "trav2", "穿透工具。Use when 测试时加载。",
                scripts={"run.py": "with open('..\\..\\etc\\passwd') as f: pass\n"})
    passed, rep = RG(bad)
    g15 = next(r for r in rep if r["gate"] == "G15-path-safety")
    check("负对照16: 反斜杠路径穿越 => G15 FAILED", not passed and g15["status"] == "FAILED")

# --- 负对照 17：G15 %2f URL 编码穿越（M8 扩展） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad17"
    write_skill(bad, "trav3", "URL编码穿透。Use when 测试时加载。",
                scripts={"run.py": "open('..%2f..%2fetc')\n"})
    passed, rep = RG(bad)
    g15 = next(r for r in rep if r["gate"] == "G15-path-safety")
    check("负对照17: %2f URL编码穿越 => G15 FAILED", not passed and g15["status"] == "FAILED")

# --- 负对照 18：G10 while 1 循环（M8 扩展） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad18"
    write_skill(bad, "loop1", "单次循环工具。Use when 测试时加载。",
                body_extra="本工具 while 1 运行循环持续轮询。\n")
    passed, rep = RG(bad)
    g10 = next(r for r in rep if r["gate"] == "G10-rogue-killswitch")
    check("负对照18: while 1 循环缺 kill-switch => G10 FAILED", not passed and g10["status"] == "FAILED")

# --- 负对照 19：G8 动态拼接命令（M8 扩展） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad19"
    write_skill(bad, "dyncmd", "动态命令工具。Use when 测试时加载。",
                scripts={"run.py": "x = input()\nos.system('echo ' + x)\n"})
    passed, rep = RG(bad)
    g8 = next(r for r in rep if r["gate"] == "G8-output-handling")
    check("负对照19: 动态拼接命令缺校验 => G8 FAILED", not passed and g8["status"] == "FAILED")

# --- 负对照 20：G4 subprocess shell=True（M8：必须 FAILED） ---
with scratch_dir() as tmp:
    bad = Path(tmp) / "bad20"
    write_skill(bad, "shshell", "命令工具。Use when 测试时加载。",
                scripts={"run.py": "import subprocess\nsubprocess.run(cmd, shell=True)\n"})
    passed, rep = RG(bad)
    g4 = next(r for r in rep if r["gate"] == "G4-injection-scan")
    check("负对照20: subprocess(shell=True) => G4 FAILED", not passed and g4["status"] == "FAILED")

# --- 反误伤对照 21：G4 安全列表式 subprocess（无 shell=True）必须 PASSED（不误伤干净代码） ---
# 这条是"负对照的负对照"：证明 M8 的 AST 加固没有把推荐的安全写法误判成危险。
with scratch_dir() as tmp:
    good = Path(tmp) / "good21"
    write_skill(good, "safelist", "执行工具。Use when 用户需要运行子进程时加载。",
                scripts={"run.py": "import subprocess\nsubprocess.run(['ls', '-la'])\n"})
    passed, rep = RG(good)
    g4 = next(r for r in rep if r["gate"] == "G4-injection-scan")
    check("反误伤21: 安全列表式 subprocess.run([...]) => G4 PASSED（不误伤）",
          passed and g4["status"] == "PASSED")

# --- fail-closed：门禁函数抛异常时不得默认放行 ---
with scratch_dir() as tmp:
    broken = Path(tmp) / "broken"
    broken.mkdir()
    # 故意让 gate_metadata 收到不存在的 SKILL.md 路径已处理；这里验证 gate_secret_scan 对坏文件不崩且 fail-closed
    (broken / "weird.bin").write_bytes(b"\x00\x01\x02")
    try:
        passed, rep = RG(broken)
        check("fail-closed: 异常/缺 SKILL.md 场景下非 PASSED（不默认放行）", not passed)
    except Exception as e:
        check("fail-closed: 抛出异常时应被捕获判 FAILED（实际崩溃）", False)
        print("  异常:", e)

# ---------------------------------------------------------------------------
# G17 发现层一致性（Agent Skills Discovery RFC v0.2.0）负/正对照
# 每个用例各自构建独立合成仓库并重取基线，避免共享计数基线导致归因错误。
# ---------------------------------------------------------------------------
def build_discovery_case(tmp, mutate_index=None, mode="local"):
    """构建合成仓库（.well-known/agent-skills/index.json + modules/demo/SKILL.md）。

    可选 mutate_index(index_dict) 在写盘前篡改索引；mode 传给 G17（local/structural）。
    返回 (all_passed, g17_result)。
    """
    root = Path(tmp) / "repo"
    (root / ".well-known" / "agent-skills").mkdir(parents=True, exist_ok=True)
    mod = root / "modules" / "demo"
    mod.mkdir(parents=True, exist_ok=True)
    md = mod / "SKILL.md"
    md.write_bytes("---\nname: demo\ndescription: 发现层一致性测试技能。Use when 需要验证 index.json 时加载。\n---\n\n# demo\n".encode("utf-8"))
    dg = "sha256:" + hashlib.sha256(md.read_bytes()).hexdigest()
    index = {
        "$schema": "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
        "skills": [
            {"name": "demo", "type": "skill-md",
             "description": "发现层一致性测试技能，用于负对照验证。",
             "url": "modules/demo/SKILL.md", "digest": dg},
        ],
    }
    if mutate_index is not None:
        mutate_index(index)
    (root / ".well-known" / "agent-skills" / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
    passed, rep = RG(mod, repo_root=root, mode=mode)
    return passed, next(r for r in rep if r["gate"] == "G17-discovery-conformance")


def _flip_hex_last(h):
    return h[:-1] + ("0" if h[-1] != "0" else "1")


# NC-G17-1: digest hex 改一位 => FAIL
with scratch_dir() as tmp:
    def _m1(idx):
        idx["skills"][0]["digest"] = "sha256:" + _flip_hex_last(idx["skills"][0]["digest"].split(":", 1)[1])
    _, g13 = build_discovery_case(tmp, _m1)
    check("G17负对照1: digest hex 改一位 => G17 FAILED", g13["status"] == "FAILED")

# NC-G17-2: 删 sha256: 前缀 => FAIL
with scratch_dir() as tmp:
    def _m2(idx):
        idx["skills"][0]["digest"] = idx["skills"][0]["digest"].split(":", 1)[1]
    _, g13 = build_discovery_case(tmp, _m2)
    check("G17负对照2: 删 sha256: 前缀 => G17 FAILED", g13["status"] == "FAILED")

# NC-G17-3: 删 entry description => FAIL
with scratch_dir() as tmp:
    def _m3(idx):
        del idx["skills"][0]["description"]
    _, g13 = build_discovery_case(tmp, _m3)
    check("G17负对照3: 删 entry description => G17 FAILED", g13["status"] == "FAILED")

# NC-G17-4: $schema 改未知 URI => FAIL
with scratch_dir() as tmp:
    def _m4(idx):
        idx["$schema"] = "https://example.com/unknown/schema.json"
    _, g13 = build_discovery_case(tmp, _m4)
    check("G17负对照4: $schema 未知 URI => G17 FAILED", g13["status"] == "FAILED")

# NC-G17-5: name 含大写 => FAIL
with scratch_dir() as tmp:
    def _m5(idx):
        idx["skills"][0]["name"] = "Demo"
    _, g13 = build_discovery_case(tmp, _m5)
    check("G17负对照5: name 含大写 => G17 FAILED", g13["status"] == "FAILED")

# NC-G17-6: name 首尾连字符 => FAIL
with scratch_dir() as tmp:
    def _m6(idx):
        idx["skills"][0]["name"] = "-demo-"
    _, g13 = build_discovery_case(tmp, _m6)
    check("G17负对照6: name 首尾连字符 => G17 FAILED", g13["status"] == "FAILED")

# NC-G17-7: url ../../etc/passwd 逃逸 => FAIL
with scratch_dir() as tmp:
    def _m7(idx):
        idx["skills"][0]["url"] = "../../etc/passwd"
    _, g13 = build_discovery_case(tmp, _m7)
    check("G17负对照7: url ../../etc/passwd 逃逸 => G17 FAILED", g13["status"] == "FAILED")

# NC-G17-8: url 绝对文件系统路径 => FAIL
with scratch_dir() as tmp:
    def _m8(idx):
        idx["skills"][0]["url"] = "C:/Windows/System32/drivers/etc/hosts"
    _, g13 = build_discovery_case(tmp, _m8)
    check("G17负对照8: url 绝对文件系统路径 => G17 FAILED", g13["status"] == "FAILED")

# NC-G17-9: url 指向不存在文件 => FAIL
with scratch_dir() as tmp:
    def _m9(idx):
        idx["skills"][0]["url"] = "modules/demo/MISSING.md"
    _, g13 = build_discovery_case(tmp, _m9)
    check("G17负对照9: url 指向不存在文件 => G17 FAILED", g13["status"] == "FAILED")

# 正对照-G17: 真实修正后的 index.json => 全门禁 PASSED 且 G17 PASSED
passed_real, rep_real = RG(ROOT / "modules" / "pdf")
g13_real = next(r for r in rep_real if r["gate"] == "G17-discovery-conformance")
check("G17正对照: 真实 index.json 合规 => 全门禁 PASSED", passed_real and g13_real["status"] == "PASSED")

# 正对照-G17b: 多一个未识别顶层键 => 告警但 PASSED（RFC：客户端 MUST 忽略未识别字段）
with scratch_dir() as tmp:
    def _m10(idx):
        idx["extra_unrecognized"] = "ignored-by-clients"
    passed_w, g13_w = build_discovery_case(tmp, _m10)
    check("G17正对照b: 未识别顶层键 => 告警但 PASSED",
          passed_w and g13_w["status"] == "PASSED" and bool(g13_w.get("warnings")))

# NC-G17-10: name 含连续连字符 => FAIL
with scratch_dir() as tmp:
    def _m11(idx):
        idx["skills"][0]["name"] = "demo--x"
    _, g17 = build_discovery_case(tmp, _m11)
    check("G17负对照10: name 含连续连字符 => G17 FAILED", g17["status"] == "FAILED")

# NC-G17-11: type 非法值 => FAIL
with scratch_dir() as tmp:
    def _m12(idx):
        idx["skills"][0]["type"] = "skill-x"
    _, g17 = build_discovery_case(tmp, _m12)
    check("G17负对照11: type 非法值 => G17 FAILED", g17["status"] == "FAILED")

# 两模式对照：远端绝对 URL 的索引 => structural 形状合规 PASSED；local 无法本地实算 => FAILED
with scratch_dir() as tmp:
    def _m13(idx):
        idx["skills"][0]["url"] = "https://cdn.example.com/v2/skills/demo/SKILL.md"
    _, g17_s = build_discovery_case(tmp, _m13, mode="structural")
    check("G17两模式1: 远端 url 在 structural 模式 => PASSED（仅校形状，不触网）", g17_s["status"] == "PASSED")
with scratch_dir() as tmp:
    def _m14(idx):
        idx["skills"][0]["url"] = "https://cdn.example.com/v2/skills/demo/SKILL.md"
    _, g17_l = build_discovery_case(tmp, _m14, mode="local")
    check("G17两模式2: 远端 url 在 local 模式 => FAILED（无法本地实算）", g17_l["status"] == "FAILED")

# G17 fail-closed：模式未指定 => FAILED（绝不静默放行）
with scratch_dir() as tmp:
    n_dir = Path(tmp) / "repo" / "modules" / "demo"
    n_dir.mkdir(parents=True, exist_ok=True)
    res_nomode = G.gate_discovery_conformance(n_dir)
    check("G17 fail-closed: 模式未指定 => FAILED", res_nomode["status"] == "FAILED")

# G17 外部正向对照：isitagentready.com 真实合规索引 => structural 模式全绿（不触网）
EXT_INDEX = ROOT.parent / "_cf_rfc_fetch" / "isitagentready.index.json"
if EXT_INDEX.is_file():
    res_ext = G.gate_discovery_conformance(ROOT, mode="structural", index_path=EXT_INDEX)
    check("G17 外部正向对照: isitagentready.index.json structural => PASSED", res_ext["status"] == "PASSED")
else:
    check("G17 外部正向对照: isitagentready.index.json 存在", False)

print("\n" + "=" * 60)
if FAILURES:
    print(f"测试结果：{len(FAILURES)} 项未通过 ❌")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
else:
    print("测试结果：全部负/正对照通过 ✅  （门禁确实能失败，且合规技能确实通过）")
    sys.exit(0)
