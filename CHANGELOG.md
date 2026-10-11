# Changelog

All notable changes to `lgd-skeleton` are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/); versioning follows SemVer.

## [1.0.0] - 2026-10-11

### Added
- fail-closed governance gates in two zero-dependency ports: `gates/gates.py` (Python stdlib) and `gates/gates.ts` (Node built-ins).
- 12 gates covering OWASP Agentic Top 10 (2026) build-time: G1 metadata, G3 secret-scan, G4 injection-scan, G5 least-privilege (ASI-02), G6 memory-poisoning (ASI-06), G7 inter-agent auth (ASI-07), G8 output-handling (ASI-05), G9 human-oversight (ASI-09), G10 rogue-kill-switch (ASI-10), G12 integrity (SHA-256), G15 path-safety, G16 ethics.
- `scaffold.py`: "say idea → generate skill skeleton + auto gates + sign card" (stdlib-only).
- 6 optional modules: `clone-site`, `github`, `pdf`, `reverse`, `mcp`, `a2a` (mcp/a2a carry G7 inter-agent auth declarations).
- AI-native discovery: `llms.txt` + `.well-known/agent-skills/index.json` (per-module SHA-256 digest; Cloudflare Agent Skills Discovery RFC v0.2.0).
- `scaffold_test.py` and `gates/gates.test.ts` negative-control suites (20 bad inputs + 1 anti-false-positive control + positive control + fail-closed; 23 checks per port).
- `OWASP-COMPLIANCE.md`: honest build-time vs runtime boundary.

### Hardened (M8, 2026-10-11)
- **G3** — added Shannon-entropy detection (string ≥ 40 chars, entropy ≥ 4.5 bit/char) to catch high-entropy single-literal fake keys; added AWS / GitHub / Slack / PGP-private-key / Supabase patterns.
- **G4** — added `os.popen` / `__import__` / `compile` / `pickle.loads` regex patterns; added a **Python-only** `ast`-based check (catches unicode-NFKC-normalized identifiers and `getattr`-obfuscation). The Python port is therefore a **conservative superset** of the TS port.
- **G15** — switched to realpath containment; added backslash (`..\..\`) and `%2f` / `%2e%2e` URL-encoding traversal detection.
- **G10** — added `while 1` and daemon / recurring loop markers.
- **G8 / G5** — broadened dynamic-command and over-broad-capability patterns.
- Added **anti-false-positive control #21**: safe list-form `subprocess.run([...])` (no `shell=True`) must remain **PASSED**.
- Red-team re-run (34 probes): **18 of 26** active-evasion probes remain bypasses; **8/8** controls blocked; **0** false positives. `SECURITY.md` *Known bypass surface* updated accordingly.
