# Security Policy

## Scope

`lgd-skeleton` is a **build-time, fail-closed governance scaffold** for Agent Skills. Its gates catch dangerous patterns **before** a skill is published or loaded:

- G3 — hardcoded secrets (API keys / tokens)
- G4 — `eval` / `exec` / `os.system` / shell injection on untrusted input
- G15 — path traversal / protected-path overwrite
- G5 — over-broad capability with no scope declaration (ASI-02)
- G6 — memory poisoning: external content in memory files without provenance (ASI-06)
- G7 — Agent-to-Agent / MCP exposure without auth declaration (ASI-07)
- G8 — untrusted input interpolated into a command without validation (ASI-05)
- G9 — high-risk action (force push / delete / publish) without human-in-the-loop (ASI-09)
- G10 — autonomous loop without a kill-switch (ASI-10)
- G16 — ethics red line (auth bypass / data theft / phishing / unauthorized access)
- G12 — integrity (per-module SHA-256 digest, verified on load)

## Honest boundary

The gates are **static / build-time** checks. They do **not** provide runtime isolation: no sandbox, no permission ring, no enforced kill-switch, no zero-trust identity. For those, pair `lgd-skeleton` with the Microsoft Agent Governance Toolkit (AGT) or container / runtime sandboxing. See `OWASP-COMPLIANCE.md` for the full build-time ↔ runtime mapping.

## Known bypass surface (honest scope)

The gates are **regex / entropy / AST heuristics**, not a semantic or runtime analyzer. An independent red-team exercise (2026-10-11), **re-run after the M8 hardening**, measured **34 probes → 18 remaining bypasses out of 26 active-evasion probes; 8/8 controls correctly blocked; 0 false positives on safe samples**. (Evidence: `_lgd_skeleton_rt_bench/rt_x_probes.py` + `x_probes_result.json`, local red-team sandbox.)

**M8 (2026-10-11) upgraded several previously-undetected classes to detected:**

| Gate | Class | Status after M8 |
|------|-------|-----------------|
| G3 secrets | high-entropy *single-literal* keys (base64 / random ≥ 40 chars) | ✅ now caught (Shannon entropy ≥ 4.5 bit/char) |
| G4 injection | `os.popen(...)` | ✅ now caught |
| G4 injection | `__import__('os').system(...)` | ✅ now caught |
| G15 path | `..%2f` / `%2e%2e` URL-encoding | ✅ now caught |
| G15 path | `..\\..\\` backslash traversal | ✅ now caught |
| G10 loop | `while 1` | ✅ now caught |
| G4 injection | full-width `ｅｖａｌ` (unicode identifier) | ⚠️ Python port caught (AST / NFKC); TS port not |

**Still-open classes (honest — remain undetected):**

| Gate | Example bypass (still passes the gate) |
|------|----------------------------------------|
| G4 injection | `'ev'+'al'(x)` string-splitting, `e/**/val(x)` comment-splitting |
| G3 secrets | `api_key = "abc"+"def"` split literal, zero-width-split variable names, `'sk-' + 'A'*20` |
| G15 path | absolute `/etc/passwd` read |
| G5 capability | `complete network access`, `full file-system access` (hyphenated) |
| G6 memory | any `来源:` / `SOURCE:` token co-located with an untrusted URL |
| G7 inter-agent | pseudo-auth word `bearer`, `httpx.post(...)` outside the keyword list |
| G8 output | `os.popen(f'...{x}')`, `subprocess.run(f'...{x}')` with a `"已校验"` / `"sanitize"` comment |
| G10 loop | `while (True)` (parenthesised), pseudo-kill-switch word `可中止` with no real exit logic |

**Deliberate non-detections (scope decisions, not defects).** `subprocess.run([...])` in list form without `shell=True` is **never flagged** — it is the *recommended safe pattern*; flagging it would create false positives on legitimate skills. A bare `open()` is likewise out of G4 scope (path safety belongs to G15).

**Port relationship.** The Python port is a **conservative superset** of the TypeScript port: both share identical regex / entropy / realpath logic, while Python additionally applies `ast.parse` (NFKC identifier normalization + structural `getattr`-obfuscation detection). A case caught by the TS port is therefore always caught by the Python port (never the reverse).

**Therefore the gates are NOT a security boundary.** They are a first-pass, low-threshold filter that (a) blocks *obvious* violations deterministically and (b) forces explicit honesty declarations. Pair `lgd-skeleton` with AGT or container / runtime sandboxing for real protection. Do not ship a skill relying on these gates alone for security.

## Reporting a vulnerability

Please report security issues **privately** (security contact TBD) instead of opening a public issue. We acknowledge within 3 business days.

## Supply chain

- Zero runtime third-party dependencies (Python stdlib / Node built-ins only).
- Per-module digests are recorded in `.well-known/agent-skills/index.json` and verified on load.
- CI runs a negative-control test suite + secret scanning on every push / PR.
