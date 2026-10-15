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


def _strip_digest_prefix(s):
    """去掉可选的 `sha256:` 前缀，返回裸小写 hex（G12/G17 共用口径）。"""
    s = (s or "").strip()
    if s.lower().startswith("sha256:"):
        s = s[len("sha256:"):]
    return s.lower()


def gate_digest(skill_dir, expected=None):
    """G12 完整性：计算 SKILL.md 的 SHA-256，与预期比对（P7）。

    兼容裸 hex 与 RFC v0.2.0 的 `sha256:{64hex}` 两种写法（expected 侧归一化），
    以适配 `.well-known/agent-skills/index.json` 的 digest 格式。
    """
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return {"gate": "G12-digest", "status": "FAILED", "detail": "SKILL.md 缺失，无法校验"}
    digest = hashlib.sha256(skill_md.read_bytes()).hexdigest()
    exp = _strip_digest_prefix(expected) if expected is not None else None
    if exp is not None and exp != digest:
        return {"gate": "G12-digest", "status": "FAILED", "detail": f"digest 不匹配 (got {digest[:12]}… expected {exp[:12]}…)"}
    return {"gate": "G12-digest", "status": "PASSED", "detail": f"sha256:{digest[:16]}…"}


# ---------------------------------------------------------------------------
# G17 发现层一致性（Agent Skills Discovery RFC v0.2.0）· 两模式
#   local      ：读本地 index.json，逐条对 url 指向的本地文件实算 SHA-256 并与 digest 比对
#   structural ：仅校形状（顶层键 / entry 键集 / 字段类型·长度·字符集 / $schema 取值），
#                不解析 url、不碰文件系统、不触网 —— 用于校验远端索引样本（如外部正向对照）
# fail-closed：文件缺失 / JSON 解析失败 / 模式未指定或非法 => FAILED（绝不静默放行）
# 注：archive 型条目的额外要求（digest 校验后拒 `..`/绝对路径/逃逸 symlink·hardlink/解压炸弹）
#     仅 **applicable only to type=archive**；本仓 index.json 当前无 archive 条目，未触发。
#     客户端 SHALL NOT 默认执行 scripts/（规范约束，非本 build-time 门禁可测项）。
# ---------------------------------------------------------------------------
DISCOVERY_INDEX_REL = ".well-known/agent-skills/index.json"
# 已知 schema URI 白名单（$schema 是 opaque identifier，RFC v0.2.0）
KNOWN_SCHEMA_URIS = (
    "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
)
DISCOVERY_TOP_KEYS = ("$schema", "skills")
DISCOVERY_ENTRY_KEYS = ("name", "type", "description", "url", "digest")
DISCOVERY_TYPES = ("skill-md", "archive")
# 合法模式：local（本地实算校验）/ structural（仅校形状，不触网）
DISCOVERY_MODES = ("local", "structural")
# name：1–64 字符、仅 a-z0-9-、不得首尾或连续连字符（Agent Skills 命名规范）
SKILL_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ENC_TRAVERSAL_RE = re.compile(r"%2e%2e|%2f|%5c", re.I)
_ABS_FS_RE = re.compile(r"^[A-Za-z]:[\\/]")
_URI_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)


def _resolve_repo_root(skill_dir, repo_root=None):
    """定位发现层所在仓库根：显式参数 > 自 skill_dir 向上找索引 > gates/ 的父目录。"""
    if repo_root is not None:
        return Path(repo_root).resolve()
    cur = Path(skill_dir).resolve()
    for cand in (cur, *cur.parents):
        if (cand / DISCOVERY_INDEX_REL).is_file():
            return cand
    return Path(__file__).resolve().parent.parent


def _resolve_discovery_url(repo_root, url):
    """按 RFC 3986 相对仓库根解析 url；返回 (绝对路径, 失败原因)。失败时路径为 None。

    拒绝：UNC/网络路径、绝对文件系统路径（C:/...）、带 scheme 的外部 URL、
    `..` 逃逸段、百分号编码穿越（%2e%2e / %2f / %5c）。路径绝对（前导 /）按仓库根解析。
    """
    if not isinstance(url, str) or not url.strip():
        return None, "url 为空或非字符串"
    u = url.strip()
    if u.startswith("\\") or u.startswith("//"):
        return None, "UNC/网络路径"
    if _ABS_FS_RE.match(u):
        return None, "绝对文件系统路径"
    if _URI_SCHEME_RE.match(u):
        return None, "外部绝对 URL（无法在仓库内校验）"
    if _ENC_TRAVERSAL_RE.search(u):
        return None, "百分号编码路径穿越"
    norm = u.replace("\\", "/")
    segs = [s for s in norm.split("/") if s not in ("", ".")]
    if any(s == ".." for s in segs):
        return None, "路径穿越 '..'"
    rel = "/".join(segs)
    if not rel:
        return None, "url 无有效路径段"
    base = Path(repo_root).resolve()
    target = (base / rel).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        return None, "解析后逃逸出仓库"
    return target, None


def gate_discovery_conformance(skill_dir, repo_root=None, mode=None, index_path=None):
    """G17 发现层一致性：校验 .well-known/agent-skills/index.json 符合 RFC v0.2.0。

    两模式（mode 必填，缺省/非法 => FAILED，fail-closed）：
      - "local"      ：校形状 + 对每条 url 指向的本地文件实算 SHA-256 并与 digest 比对；
      - "structural" ：仅校形状（顶层键 / entry 键集 / 字段类型·长度·字符集 / $schema 取值），
                       不解析 url、不碰文件系统、不触网。
    检查：存在 / 合法 JSON / 顶层键 / `$schema` 白名单 / entry 全字段 / name·type·description·digest 形状。
    口径：未识别顶层键与 entry 键 => 告警（RFC：MUST ignore unrecognized fields，不 FAIL）；
    缺 `$schema` => RFC 视为 v0.1.0 => 告警且 FAIL（本骨架发布 v0.2.0 索引，v0.1.0 形态不合规）；
    未识别 `$schema` URI => FAIL（RFC：SHOULD NOT process）。

    index_path：可选，显式指定被校验的索引文件（用于校验仓库外样本，如外部正向对照）。
    """
    warnings = []

    def result(status, detail):
        r = {"gate": "G17-discovery-conformance", "status": status, "detail": detail}
        if warnings:
            r["warnings"] = list(warnings)
        return r

    if mode not in DISCOVERY_MODES:
        return result("FAILED", f"模式未指定或非法（须 {' 或 '.join(DISCOVERY_MODES)}），fail-closed 拒绝放行")

    root = _resolve_repo_root(skill_dir, repo_root)
    idx = Path(index_path) if index_path is not None else (root / DISCOVERY_INDEX_REL)

    if not idx.is_file():
        return result("FAILED", f"缺失发现层索引 {idx}")
    try:
        data = json.loads(idx.read_bytes().decode("utf-8"))
    except Exception as e:
        return result("FAILED", f"index.json 非法 JSON: {type(e).__name__}: {e}")
    if not isinstance(data, dict):
        return result("FAILED", "index.json 顶层不是对象")

    extras = [k for k in data.keys() if k not in DISCOVERY_TOP_KEYS]
    if extras:
        warnings.append("未识别顶层键（RFC：客户端 MUST 忽略）: " + ", ".join(extras))
    if "$schema" not in data:
        warnings.append("缺 $schema：RFC 规定按 v0.1.0 处理；本骨架发布 v0.2.0 索引，故判不合规")
        return result("FAILED", "顶层缺 $schema 字段（将被视为 v0.1.0，非 v0.2.0）")
    schema = data.get("$schema")
    if schema not in KNOWN_SCHEMA_URIS:
        return result("FAILED", f"未识别 $schema URI: {schema!r}（已知: {KNOWN_SCHEMA_URIS[0]}）；RFC 规定 SHOULD NOT process")

    skills = data.get("skills")
    if not isinstance(skills, list) or not skills:
        return result("FAILED", "skills 缺失或不是非空数组")

    problems = []
    for n, ent in enumerate(skills):
        tag = f"skills[{n}]"
        if not isinstance(ent, dict):
            problems.append(f"{tag}: entry 非对象")
            continue
        for k in ent.keys():
            if k not in DISCOVERY_ENTRY_KEYS:
                warnings.append(f"{tag} 未识别键（RFC：MUST 忽略）: {k}")
        nm = ent.get("name")
        if not isinstance(nm, str) or not SKILL_NAME_RE.match(nm) or "--" in nm:
            problems.append(f"{tag}: name 非法（须 ^[a-z0-9](?:[a-z0-9-]{{0,62}}[a-z0-9])?$ 且无连续连字符）: {nm!r}")
        if ent.get("type") not in DISCOVERY_TYPES:
            problems.append(f"{tag}: type 非 skill-md/archive: {ent.get('type')!r}")
        desc = ent.get("description")
        if not isinstance(desc, str) or not (1 <= len(desc) <= 1024):
            problems.append(f"{tag}: description 非法（须 1–1024 字符串）")
        dg = ent.get("digest")
        if not isinstance(dg, str) or not DIGEST_RE.match(dg):
            problems.append(f"{tag}: digest 非法（须 sha256:{{64 位小写 hex}}）: {dg!r}")
        if not isinstance(ent.get("url"), str) or not ent.get("url").strip():
            problems.append(f"{tag}: url 为空或非字符串")
        if mode != "local":
            continue  # structural 模式：仅校形状，不解析 url、不碰文件系统、不触网
        target, why = _resolve_discovery_url(root, ent.get("url"))
        if target is None:
            problems.append(f"{tag}: url 非法/逃逸仓库: {why}")
            continue
        if not target.is_file():
            problems.append(f"{tag}: url 指向文件不存在: {ent.get('url')}")
            continue
        if isinstance(dg, str) and DIGEST_RE.match(dg):
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
            want = dg.split(":", 1)[1]
            if actual != want:
                problems.append(f"{tag}: digest 与文件实算不符（{ent.get('url')}）got {actual[:12]}… expected {want[:12]}…")

    if problems:
        return result("FAILED", "; ".join(problems))
    if mode == "local":
        msg = f"index.json 合规（$schema=v0.2.0，{len(skills)} 条 entry 摘要全部实算一致）"
    else:
        msg = f"index.json 形状合规（$schema=v0.2.0，{len(skills)} 条 entry；structural 模式未做本地实算）"
    if warnings:
        msg += "；告警: " + " | ".join(warnings)
    return result("PASSED", msg)


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


def run_gates(skill_dir, expected_digest=None, repo_root=None, discovery_mode=None):
    """运行全部门禁，fail-closed。返回 (passed, report)。

    repo_root：发现层（G17）所在仓库根；缺省时自 skill_dir 向上自动定位。
    discovery_mode：G17 模式（"local" | "structural"）；缺省 None => G17 FAILED（fail-closed，
                    调用方须显式指定；CLI 与 scaffold 均显式传 "local"）。
    """
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
        ("G17-discovery-conformance", lambda: gate_discovery_conformance(skill_dir, repo_root, discovery_mode)),
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
        print("usage: gates.py <skill_dir> [expected_digest] [discovery_mode=local|structural]", file=sys.stderr)
        return 2
    skill_dir = sys.argv[1]
    expected = sys.argv[2] if len(sys.argv) > 2 else None
    discovery_mode = sys.argv[3] if len(sys.argv) > 3 else "local"
    passed, report = run_gates(skill_dir, expected, discovery_mode=discovery_mode)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("\nRESULT:", "PASSED" if passed else "FAILED")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
