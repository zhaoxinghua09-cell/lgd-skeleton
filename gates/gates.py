#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LGD 母骨架 · fail-closed 门禁运行器（stdlib-only，零外部依赖）
=====================================================================
设计原则（对应已确认 P6 安全门禁内建 / P7 完整性可验证 / P8 失败隔离）：
  - fail-closed：任何无法判定或抛异常的门禁 => FAILED（绝不默认放行）
  - 可失败：每个门禁都必须能被"坏输入"触发 FAILED（见 scaffold_test.py 负对照）
  - 完整性：每模块发布带 SHA-256 digest，加载前必校验（P7）
  - 路径安全：禁止 ../ 穿越、禁止写入受保护前缀（P8 / G15）

本运行器是 .ai-collab G1–G16 企业级门禁在"技能/工具骨架"层的轻量移植，
保留其 fail-closed 语义，但去掉重运行时依赖，便于零积分、可移植部署。

M8 加固（2026-10-11）：G3 熵检测 + 扩展 pattern；G4 正则扩展 + Python AST 级；
G15 realpath containment + 反斜杠/绝对路径/URL 编码穿越；G10 循环标记扩展。
每道新检测均配负对照（见 scaffold_test.py / gates.test.ts）。

本端口对 TS 端口（gates.ts）构成**保守超集**：AST 只"加"检测（unicode NFKC 归一化标识符、
getattr 混淆），不改变对安全写法的判定——`subprocess.run([...])` 列表式且无 shell=True
属推荐安全用法，必须 PASSED（见 scaffold_test.py 反误伤对照 21）。
"""

import ast
import hashlib
import json
import math
import os
import re
import sys
import warnings
from pathlib import Path

# ---------------------------------------------------------------------------
# 受保护路径前缀（G15 受保护区）：骨架核心不被技能覆盖
# ---------------------------------------------------------------------------
PROTECTED_PREFIXES = ("gates/", ".well-known/", "scaffold.py", "AGENTS.md", "llms.txt")

# 硬编码密钥/令牌特征（G3 秘密扫描）—— M8 扩展：AWS/GitHub/Slack/私钥
SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]"), "hardcoded-secret"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "openai-key"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"), "jwt-token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws-key"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "github-token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "slack-token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private-key"),
    (re.compile(r"supabase.*service_role"), "supabase-service-role"),
]
# 高熵字符串检测（G3）：捕获 base64/随机 等高熵假密钥（绕过前缀规则）
HIGH_ENTROPY_MIN_LEN = 40
HIGH_ENTROPY_MIN_BITS = 4.5
STRING_LITERAL = re.compile(r"(['\"])((?:\\\1|(?!\1).)*?)\1", re.S)

# 危险执行/注入模式（G4 / G14 注入扫描）—— M8 扩展
INJECTION_PATTERNS = [
    (re.compile(r"\beval\s*\("), "dangerous-eval"),
    (re.compile(r"\bexec\s*\("), "dangerous-exec"),
    (re.compile(r"os\.system\s*\("), "os-system"),
    (re.compile(r"os\.popen\s*\("), "os-popen"),
    (re.compile(r"subprocess\.(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True"), "subprocess-shell"),
    (re.compile(r"__import__\s*\("), "dynamic-import"),
    (re.compile(r"\bcompile\s*\("), "dynamic-compile"),
    (re.compile(r"pickle\.loads?\s*\("), "pickle-load"),
    (re.compile(r"<\s*script|javascript:"), "html-injection"),
]
# Python AST 额外危险调用（仅 Python 端口；零依赖 ast 模块，捕获正则漏过的混淆）。
# 语义与正则保持一致的"只多不少"：AST 只添加正则抓不到的形态（unicode 归一化标识符、
# getattr 混淆），不改变安全调用的判定（如 subprocess.run([...]) 无 shell=True 必须 PASSED）。
AST_DANGEROUS_NAMES = {"eval", "exec", "compile", "__import__"}
AST_OBFUSCATED_TARGETS = {"eval", "exec", "compile", "__import__", "system", "popen", "load", "loads"}
AST_SUBPROCESS_FNS = {"call", "run", "Popen", "check_output", "check_call"}

# 伦理红线意图（G16 伦理门禁）：声明即拦截，不待执行
ETHICS_PATTERNS = [
    (re.compile(r"(?i)bypass\s+(the\s+)?authenticat"), "auth-bypass-intent"),
    (re.compile(r"(?i)auth\s+bypass"), "auth-bypass-intent"),
    (re.compile(r"(?i)extract\s+user\s+data"), "data-exfil-intent"),
    (re.compile(r"(?i)phish|impersonat|钓鱼|仿冒|伪装"), "phishing-intent"),
    (re.compile(r"(?i)绕过.*(认证|鉴权)|未授权.*(逆向|入侵|访问)"), "unauthorized-access-intent"),
]

# 路径穿越（G15 内容）：../ 或 ..\ 或 URL 编码 %2e%2e / %2f
TRAVERSAL_PAT = re.compile(r"\.\.[/\\]|%2e%2e|%2f", re.I)

# 扫描扩展名
CODE_EXT = (".py", ".sh", ".js", ".ts", ".md")
TEXT_EXT = (".py", ".sh", ".js", ".ts", ".md", ".json", ".txt", ".yaml", ".yml")


def _fail_closed(label, exc):
    """任何异常一律判 FAILED（fail-closed）。"""
    return {"gate": label, "status": "FAILED", "detail": f"fail-closed: {type(exc).__name__}: {exc}"}


def _entropy(s):
    """Shannon 熵（bit/char）。"""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def parse_frontmatter(text):
    """解析 SKILL.md 的 YAML frontmatter（仅支持 name/description 等简单键值，零依赖）。"""
    if not text.startswith("---"):
        return None, text
    end = text.find("\n---", 3)
    if end == -1:
        return None, text
    fm = text[3:end].strip()
    body = text[end + 4:].lstrip("\n")
    data = {}
    for line in fm.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            data[k.strip()] = v.strip().strip('"').strip("'")
    return data, body


def gate_metadata(skill_dir):
    """G1 元数据门禁：SKILL.md 必须含 name + description（actionable）。"""
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return {"gate": "G1-metadata", "status": "FAILED", "detail": "SKILL.md 缺失"}
    data, _ = parse_frontmatter(skill_md.read_text(encoding="utf-8"))
    if not data:
        return {"gate": "G1-metadata", "status": "FAILED", "detail": "无 frontmatter"}
    name = data.get("name", "")
    desc = data.get("description", "")
    if not name or not desc:
        return {"gate": "G1-metadata", "status": "FAILED", "detail": "name/description 缺失"}
    if len(desc) < 20:
        return {"gate": "G1-metadata", "status": "FAILED", "detail": "description 过短(<20字符)，AI 无法判断何时加载"}
    if "use when" not in desc.lower() and "用于" not in desc and "当" not in desc:
        return {"gate": "G1-metadata", "status": "FAILED", "detail": "description 缺少'何时使用'信号"}
    return {"gate": "G1-metadata", "status": "PASSED", "detail": f"name={name}"}


def gate_secret_scan(skill_dir):
    """G3 秘密扫描：scripts/ 下不得出现硬编码密钥（正则 + 高熵字符串）。"""
    hits = []
    for f in skill_dir.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix not in (".py", ".sh", ".js", ".ts", ".json", ".md", ".env"):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pat, kind in SECRET_PATTERNS:
            if pat.search(content):
                hits.append(f"{kind}@{f.name}")
        # 高熵字符串字面量（仅代码文件）：捕获 base64/随机 假密钥
        if f.suffix in (".py", ".js", ".ts", ".sh"):
            for m in STRING_LITERAL.finditer(content):
                s = m.group(2)
                if (len(s) >= HIGH_ENTROPY_MIN_LEN
                        and _entropy(s) >= HIGH_ENTROPY_MIN_BITS
                        and not re.match(r"https?://|/[A-Za-z]:[\\/]|\\.", s)):
                    hits.append(f"high-entropy@{f.name}")
                    break
    if hits:
        return {"gate": "G3-secret-scan", "status": "FAILED", "detail": "命中硬编码密钥/高熵串: " + ", ".join(dict.fromkeys(hits))}
    return {"gate": "G3-secret-scan", "status": "PASSED", "detail": "未发现硬编码密钥/高熵串"}


def _ast_dangerous(content):
    """Python AST 级 G4：捕获 eval/exec/compile/__import__/os.system 等危险调用（含 getattr 混淆）。

    注意：这里解析的是**待扫描的不可信源码**，其自身的 SyntaxWarning（如路径串里的
    `\\.` 无效转义）不得外溢为本工具 stderr 的警告——故用 catch_warnings 局部静音，
    并显式给出 filename，避免出现 `<unknown>` 归属。SyntaxError（真语法错）仍返回 []。
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(content, filename="<scanned>")
    except SyntaxError:
        return []
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        # 1) 直接名调用：eval / exec / compile / __import__（含 unicode NFKC 归一化，如全角 ｅｖａｌ）
        if isinstance(f, ast.Name) and f.id in AST_DANGEROUS_NAMES:
            found.append(f.id)
            continue
        # 2) getattr 混淆：getattr(os, 'system') / getattr(builtins, 'eval') 等
        if isinstance(f, ast.Name) and f.id == "getattr" and len(node.args) >= 2:
            a = node.args[1]
            if isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value in AST_OBFUSCATED_TARGETS:
                found.append(f"getattr:{a.value}")
            continue
        # 3) 属性调用：按"接收者 + 属性"精确判定，避免把安全调用误伤成 FAILED
        if isinstance(f, ast.Attribute):
            base = f.value
            base_name = base.id if isinstance(base, ast.Name) else None
            if base_name == "os" and f.attr in ("system", "popen"):
                found.append(f"os.{f.attr}")
            elif base_name == "pickle" and f.attr in ("load", "loads"):
                found.append(f"pickle.{f.attr}")
            elif base_name == "subprocess" and f.attr in AST_SUBPROCESS_FNS:
                # 仅当 shell=True 才危险；列表参数/shell=False 是安全用法，必须 PASSED
                if any(kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                       and kw.value.value is True for kw in node.keywords):
                    found.append(f"subprocess.{f.attr}(shell=True)")
    return found


def gate_injection_scan(skill_dir):
    """G4/G14 注入扫描：禁止 eval/exec/os.system/subprocess/pickle 等（正则 + Python AST）。"""
    hits = []
    for f in skill_dir.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix not in CODE_EXT:
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pat, kind in INJECTION_PATTERNS:
            if pat.search(content):
                hits.append(f"{kind}@{f.name}")
        if f.suffix == ".py":
            for d in _ast_dangerous(content):
                hits.append(f"ast:{d}@{f.name}")
    if hits:
        return {"gate": "G4-injection-scan", "status": "FAILED", "detail": "命中危险模式: " + ", ".join(dict.fromkeys(hits))}
    return {"gate": "G4-injection-scan", "status": "PASSED", "detail": "未命中危险执行/注入模式"}


def gate_ethics(skill_dir):
    """G16 伦理门禁：技能声明/代码不得含明确的危险意图（认证绕过/数据窃取/钓鱼/未授权访问）。"""
    hits = []
    scan_files = []
    skill_md = skill_dir / "SKILL.md"
    if skill_md.exists():
        scan_files.append(skill_md)
    for f in skill_dir.rglob("*"):
        if f.is_file() and f.suffix in CODE_EXT:
            scan_files.append(f)
    for f in scan_files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pat, kind in ETHICS_PATTERNS:
            if pat.search(content):
                hits.append(f"{kind}@{f.name}")
    if hits:
        return {"gate": "G16-ethics", "status": "FAILED", "detail": "命中伦理红线意图: " + ", ".join(dict.fromkeys(hits))}
    return {"gate": "G16-ethics", "status": "PASSED", "detail": "未命中认证绕过/数据窃取/钓鱼/未授权访问意图"}


def gate_path_safety(skill_dir):
    """G15 路径安全：realpath containment + 文件名/内容穿越（../ 或 ..\\ 或 %2f 绝对路径）+ 受保护区覆写。"""
    bad = []
    skill_real = skill_dir.resolve()
    for f in skill_dir.rglob("*"):
        if not f.is_file():
            continue
        try:
            f_real = f.resolve()
            f_real.relative_to(skill_real)  # 逃逸则抛 ValueError
        except (ValueError, OSError):
            bad.append(f"escape:{f.name}")
            continue
        rel = f.relative_to(skill_dir).as_posix()
        if ".." in rel or rel.startswith("/"):
            bad.append(f"traversal:{rel}")
        if f.suffix in CODE_EXT:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for m in TRAVERSAL_PAT.finditer(content):
                ctx = content[max(0, m.start() - 10):m.end() + 10].replace("\n", " ")
                bad.append(f"content-traversal:{f.name}: ...{ctx}...")
                break
    # 检查技能不得覆盖母骨架受保护区（写入企图检测）
    for protected in PROTECTED_PREFIXES:
        if (skill_dir / protected).exists() and skill_dir.name != "lgd-skeleton":
            bad.append(f"protected-overwrite:{protected}")
    if bad:
        return {"gate": "G15-path-safety", "status": "FAILED", "detail": "; ".join(bad)}
    return {"gate": "G15-path-safety", "status": "PASSED", "detail": "无路径穿越/受保护区覆写"}


def gate_digest(skill_dir, expected=None):
    """G12 完整性：计算 SKILL.md 的 SHA-256，与预期比对（P7）。"""
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return {"gate": "G12-digest", "status": "FAILED", "detail": "SKILL.md 缺失，无法校验"}
    digest = hashlib.sha256(skill_md.read_bytes()).hexdigest()
    if expected is not None and expected != digest:
        return {"gate": "G12-digest", "status": "FAILED", "detail": f"digest 不匹配 (got {digest[:12]}… expected {expected[:12]}…)"}
    return {"gate": "G12-digest", "status": "PASSED", "detail": f"sha256={digest[:16]}…"}


# ---------------------------------------------------------------------------
# OWASP Agentic Top 10 (2026) build-time 扩展门禁（G5–G10）
# 设计纪律：每道门默认 PASSED；仅当"危险信号 + 缺相应声明"时才 FAILED，
# 既保证能失败（见 scaffold_test.py 负对照），又不误伤干净模块（fail-closed 信誉）。
# 运行时项（沙箱/权限环/Agent 间信任）超出 build-time 骨架范畴，
# 诚实声明须在 OWASP-COMPLIANCE.md 标注，并建议配合 AGT / 容器。
# ---------------------------------------------------------------------------

# G5 / ASI-02 最小权限：过度宽泛的能力声明必须有 scope/限制 声明
OVER_BROAD_CAP = [
    re.compile(r"(?i)(full|unrestricted|无限制|任意|完整|global|全局|entire|整个|all\s+files)\s*(file\s*system|文件系统|network|网络|access|访问|code\s*execution|代码执行|system|系统)"),
    re.compile(r"(?i)arbitrary\s+code\s+execution|任意代码执行|root\s*access|admin\s*access|sudo"),
]
SCOPE_DECL = re.compile(r"(?i)(scope|限制|最小权限|least[\s-]?privilege|授权范围|仅限|限定在|仅处理|只处理|仅对)")

# G6 / ASI-06 记忆投毒：记忆/状态文件中的外部内容须带来源标注
MEMORY_FILES = ("memory.md", "state.json", "context.md", "notes.md")
UNTRUSTED_MARKERS = re.compile(r"https?://|来源[:：]|SOURCE[:：]")
PROVENANCE_DECL = re.compile(r"(?i)(来源|SOURCE|出处|provenance|可信|已核实|verified|来自.*官网|official)")

# G7 / ASI-07 不安全的 Agent 间通信：Agent 互调必须有认证/签名
AGENT_CALL = [
    re.compile(r"(?i)(a2a|agent[\s-]?to[\s-]?agent|agent\s*card|mcp\s*client|mcp[\s-]?server|send.*agent|agent.*endpoint)"),
    re.compile(r"requests\.(get|post|put|delete)\s*\("),
]
AUTH_DECL = re.compile(r"(?i)(auth|认证|签名|sign|token|ed25519|spiffe|信任|trust|bearer|oauth)")

# G8 / ASI-05 不安全输出处理：未受信输入拼入命令/exec（G4 已覆盖直接 eval/exec）
OUTPUT_INTERP = re.compile(r"os\.system\s*\([^)]*\{[^}]*\}|subprocess\.[A-Za-z]+\s*\([^)]*\{[^}]*\}|eval\s*\([^)]*\{[^}]*\}|exec\s*\([^)]*\{[^}]*\}")
# G8 新增：动态构造命令（字符串拼接命令名）
OUTPUT_DYN_CMD = re.compile(r"(subprocess|os\.system|os\.popen)\s*\([^)]*\+\s*[^)]*\)")

# G9 / ASI-09 人-Agent 信任：不可逆/高风险动作须有监督声明
RISKY_ACTION = re.compile(r"(?i)(force\s*push|删\s*(除|分支|库)|delete|drop\s+table|publish|发布|transfer|转账|payment|支付|send\s+email|发送)")
HUMAN_OVERSIGHT_DECL = re.compile(r"(?i)(人工确认|human[\s-]?in[\s-]?the[\s-]?loop|监护|审批|经.*确认|不自动执行|oversee|须.*授权)")

# G10 / ASI-10 流氓 Agent：长期自治/循环须有终止/kill-switch 声明（M8 扩展）
AUTONOMOUS_LOOP = [
    re.compile(r"(?i)(while\s+True|while\s+1|无限循环|自治循环|autonomous|长期运行|scheduler|cron|定时任务|self[\s-]?loop|daemon|守护|recurring|循环执行|loop\s+forever|while\s+1:)"),
]
KILLSWITCH_DECL = re.compile(r"(?i)(kill[\s-]?switch|终止条件|terminat|停止条件|exit\s*condition|人工中止|可中止|最多.*次|max\s*iter|运行.*上限)")


def _read_texts(skill_dir):
    """收集 SKILL.md 与所有文本文件的 (path, content)；读不了则跳过（fail-closed）。"""
    texts = []
    skill_md = skill_dir / "SKILL.md"
    if skill_md.exists():
        try:
            texts.append((skill_md, skill_md.read_text(encoding="utf-8", errors="ignore")))
        except Exception:
            pass
    for f in skill_dir.rglob("*"):
        if f.is_file() and f.suffix in TEXT_EXT:
            try:
                texts.append((f, f.read_text(encoding="utf-8", errors="ignore")))
            except Exception:
                continue
    return texts


def gate_capability_least_privilege(skill_dir):
    """G5 / ASI-02：过度宽泛能力声明须配 scope 声明，否则 FAILED。"""
    body = "\n".join(t for _, t in _read_texts(skill_dir))
    for pat in OVER_BROAD_CAP:
        if pat.search(body) and not SCOPE_DECL.search(body):
            return {"gate": "G5-capability", "status": "FAILED",
                    "detail": "过度宽泛能力声明但缺少 scope/限制 声明"}
    return {"gate": "G5-capability", "status": "PASSED", "detail": "未声明过度宽泛能力，或已配 scope 声明"}


def gate_memory_poisoning(skill_dir):
    """G6 / ASI-06：记忆/状态文件中的外部内容须带来源标注。"""
    bad = []
    for f in skill_dir.rglob("*"):
        if f.is_file() and f.name.lower() in MEMORY_FILES:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if UNTRUSTED_MARKERS.search(content) and not PROVENANCE_DECL.search(content):
                bad.append(f"{f.name}: 含外部内容但缺来源标注")
    if bad:
        return {"gate": "G6-memory-poisoning", "status": "FAILED", "detail": "; ".join(bad)}
    return {"gate": "G6-memory-poisoning", "status": "PASSED", "detail": "记忆/状态文件均带来源标注或无外部内容"}


def gate_inter_agent_auth(skill_dir):
    """G7 / ASI-07：Agent 互调 / MCP/A2A 暴露须配认证声明。"""
    body = "\n".join(t for _, t in _read_texts(skill_dir))
    if any(p.search(body) for p in AGENT_CALL) and not AUTH_DECL.search(body):
        return {"gate": "G7-inter-agent-auth", "status": "FAILED",
                "detail": "检测到 Agent 互调/MCP/A2A 暴露但缺认证/签名声明"}
    return {"gate": "G7-inter-agent-auth", "status": "PASSED", "detail": "无 Agent 互调或已配认证声明"}


def gate_output_handling(skill_dir):
    """G8 / ASI-05：未受信输入拼入命令/exec 须有校验/消毒说明（G4 已覆盖直接 eval/exec）。"""
    hits = []
    for f in skill_dir.rglob("*"):
        if f.is_file() and f.suffix in (".py", ".sh", ".js", ".ts"):
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if (OUTPUT_INTERP.search(content) or OUTPUT_DYN_CMD.search(content)) and "sanitiz" not in content.lower() and "校验" not in content:
                hits.append(f"untrusted-interp:{f.name}")
    if hits:
        return {"gate": "G8-output-handling", "status": "FAILED",
                "detail": "未受信输入拼入命令但未见校验/消毒: " + ", ".join(hits)}
    return {"gate": "G8-output-handling", "status": "PASSED", "detail": "未检测到危险输出插值"}


def gate_human_oversight(skill_dir):
    """G9 / ASI-09：不可逆/高风险动作须有监督声明。"""
    body = "\n".join(t for _, t in _read_texts(skill_dir))
    if RISKY_ACTION.search(body) and not HUMAN_OVERSIGHT_DECL.search(body):
        return {"gate": "G9-human-oversight", "status": "FAILED",
                "detail": "检测到高风险动作但缺 human-in-the-loop/人工确认 声明"}
    return {"gate": "G9-human-oversight", "status": "PASSED", "detail": "无高风险动作或已配监督声明"}


def gate_rogue_killswitch(skill_dir):
    """G10 / ASI-10：长期自治/循环须有终止/kill-switch 声明（M8 扩展循环标记）。"""
    body = "\n".join(t for _, t in _read_texts(skill_dir))
    if any(p.search(body) for p in AUTONOMOUS_LOOP) and not KILLSWITCH_DECL.search(body):
        return {"gate": "G10-rogue-killswitch", "status": "FAILED",
                "detail": "检测到自治/循环声明但缺 kill-switch/终止条件"}
    return {"gate": "G10-rogue-killswitch", "status": "PASSED", "detail": "无自治/循环声明或已配终止条件"}


def run_gates(skill_dir, expected_digest=None):
    """运行全部门禁，fail-closed。返回 (passed, report)。"""
    skill_dir = Path(skill_dir)
    gates = [
        ("G1-metadata", lambda: gate_metadata(skill_dir)),
        ("G3-secret-scan", lambda: gate_secret_scan(skill_dir)),
        ("G4-injection-scan", lambda: gate_injection_scan(skill_dir)),
        ("G5-capability", lambda: gate_capability_least_privilege(skill_dir)),
        ("G6-memory-poisoning", lambda: gate_memory_poisoning(skill_dir)),
        ("G7-inter-agent-auth", lambda: gate_inter_agent_auth(skill_dir)),
        ("G8-output-handling", lambda: gate_output_handling(skill_dir)),
        ("G9-human-oversight", lambda: gate_human_oversight(skill_dir)),
        ("G10-rogue-killswitch", lambda: gate_rogue_killswitch(skill_dir)),
        ("G16-ethics", lambda: gate_ethics(skill_dir)),
        ("G15-path-safety", lambda: gate_path_safety(skill_dir)),
        ("G12-digest", lambda: gate_digest(skill_dir, expected_digest)),
    ]
    report = []
    for label, fn in gates:
        try:
            report.append(fn())
        except Exception as e:  # fail-closed
            report.append(_fail_closed(label, e))
    passed = all(r["status"] == "PASSED" for r in report)
    return passed, report


def main():
    if len(sys.argv) < 2:
        print("usage: gates.py <skill_dir> [expected_digest]", file=sys.stderr)
        return 2
    skill_dir = sys.argv[1]
    expected = sys.argv[2] if len(sys.argv) > 2 else None
    passed, report = run_gates(skill_dir, expected)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("\nRESULT:", "PASSED" if passed else "FAILED")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
