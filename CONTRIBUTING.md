# Contributing

`lgd-skeleton` uses a Git-native, AI-friendly contribution flow (inspired by Tencent teamAI): push candidate → review & merge → pull.

## For humans

1. Fork / branch.
2. Add or change a module under `modules/` via `python scaffold.py "your idea"` — never hand-write a module to bypass the gates.
3. Run gates:
   - `python gates/gates.py modules/<name>`
   - `node --experimental-strip-types gates/gates.ts modules/<name>`
   - Both must report **PASSED**.
4. Run the test suites:
   - `python scaffold_test.py`
   - `node --experimental-strip-types gates/gates.test.ts`
5. Open a MR / PR. CI must be green (Python + Node tests + secret scan).

## For AI agents

Read `AGENTS.md` first — it is the single source of truth for the gate hooks and the nine-sound (九声) / LGD constitution injected into every agent. AI contributors cannot skip the gates.

## Releasing

Bump `VERSION` and add a `CHANGELOG.md` entry. Tags follow SemVer (`vMAJOR.MINOR.PATCH`).
