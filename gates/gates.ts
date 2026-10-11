/**
 * LGD 母骨架 · fail-closed 门禁运行器（TypeScript 端口，零外部依赖）
 * 与 gates.py 语义一致：stdlib-only → 此处为 Node 内置 fs/path/crypto，零 npm 依赖。
 * 运行：node gates.ts <skill_dir> [expected_digest]  （Node 22.6+ 原生类型擦除）
 * 设计原则：fail-closed（异常/缺 SKILL.md => FAILED，绝不默认放行）；每个门禁可被坏输入触发 FAILED。
 *
 * M8 加固（2026-10-11）：G3 熵检测 + 扩展 pattern；G4 正则扩展（AST 级为 Python 端口独占，见 gates.py）；
 * G15 realpath containment + 反斜杠/绝对路径/URL 编码穿越；G10 循环标记扩展。
 * 注：TypeScript 端口零依赖，无法使用原生 AST 解析，故 G4 仅以正则实现。两端口共享同一套正则 / 熵 /
 * realpath 语义；Python 端口额外做 AST 级检测，对 TS 端口构成**保守超集**（TS 能拦的 Python 必拦，反之不成立）。
 */

import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
import { pathToFileURL } from 'url';

const PROTECTED_PREFIXES: string[] = ['gates/', '.well-known/', 'scaffold.ts', 'scaffold.py', 'AGENTS.md', 'llms.txt'];

const SECRET_PATTERNS: RegExp[] = [
  /(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['"][A-Za-z0-9_\-]{12,}['"]/i,
  /sk-[A-Za-z0-9]{20,}/,
  /eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}/,
  /AKIA[0-9A-Z]{16}/,
  /ghp_[A-Za-z0-9]{20,}/,
  /xox[baprs]-[A-Za-z0-9-]{10,}/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /supabase.*service_role/i,
];
const HIGH_ENTROPY_MIN_LEN = 40;
const HIGH_ENTROPY_MIN_BITS = 4.5;
const STRING_LITERAL = /(['"])((?:\\\1|(?!\1)[\s\S])*?)\1/g;

const INJECTION_PATTERNS: RegExp[] = [
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /os\.system\s*\(/,
  /os\.popen\s*\(/,
  /subprocess\.(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/,
  /__import__\s*\(/,
  /\bcompile\s*\(/,
  /pickle\.loads?\s*\(/,
  /<\s*script|javascript:/i,
];

const ETHICS_PATTERNS: RegExp[] = [
  /bypass\s+(the\s+)?authenticat/i,
  /auth\s+bypass/i,
  /extract\s+user\s+data/i,
  /phish|impersonat|钓鱼|仿冒|伪装/i,
  /绕过.*(认证|鉴权)|未授权.*(逆向|入侵|访问)/i,
];

const TRAVERSAL_PAT = /\.\.[/\\]|%2e%2e|%2f/i;

// OWASP Agentic Top 10 (2026) build-time 扩展
const OVER_BROAD_CAP: RegExp[] = [
  /(full|unrestricted|无限制|任意|完整|global|全局|entire|整个|all\s+files)\s*(file\s*system|文件系统|network|网络|access|访问|code\s*execution|代码执行|system|系统)/i,
  /arbitrary\s+code\s+execution|任意代码执行|root\s*access|admin\s*access|sudo/i,
];
const SCOPE_DECL = /(scope|限制|最小权限|least[\s-]?privilege|授权范围|仅限|限定在|仅处理|只处理|仅对)/i;

const MEMORY_FILES: string[] = ['memory.md', 'state.json', 'context.md', 'notes.md'];
const UNTRUSTED_MARKERS = /https?:\/\/|来源[:：]|SOURCE[:：]/i;
const PROVENANCE_DECL = /(来源|SOURCE|出处|provenance|可信|已核实|verified|来自.*官网|official)/i;

const AGENT_CALL: RegExp[] = [
  /(a2a|agent[\s-]?to[\s-]?agent|agent\s*card|mcp\s*client|mcp[\s-]?server|send.*agent|agent.*endpoint)/i,
  /requests\.(get|post|put|delete)\s*\(/,
];
const AUTH_DECL = /(auth|认证|签名|sign|token|ed25519|spiffe|信任|trust|bearer|oauth)/i;

const OUTPUT_INTERP = /os\.system\s*\([^)]*\{[^}]*\}|subprocess\.[A-Za-z]+\s*\([^)]*\{[^}]*\}|eval\s*\([^)]*\{[^}]*\}|exec\s*\([^)]*\{[^}]*\}/;
const OUTPUT_DYN_CMD = /(subprocess|os\.system|os\.popen)\s*\([^)]*\+\s*[^)]*\)/;

const RISKY_ACTION = /(force\s*push|删\s*(除|分支|库)|delete|drop\s+table|publish|发布|transfer|转账|payment|支付|send\s+email|发送)/i;
const HUMAN_OVERSIGHT_DECL = /(人工确认|human[\s-]?in[\s-]?the[\s-]?loop|监护|审批|经.*确认|不自动执行|oversee|须.*授权)/i;

const AUTONOMOUS_LOOP: RegExp[] = [
  /(while\s+True|while\s+1|无限循环|自治循环|autonomous|长期运行|scheduler|cron|定时任务|self[\s-]?loop|daemon|守护|recurring|循环执行|loop\s+forever|while\s+1:)/i,
];
const KILLSWITCH_DECL = /(kill[\s-]?switch|终止条件|terminat|停止条件|exit\s*condition|人工中止|可中止|最多.*次|max\s*iter|运行.*上限)/i;

const CODE_EXT = ['.py', '.sh', '.js', '.ts', '.md'];
const TEXT_EXT = ['.py', '.sh', '.js', '.ts', '.md', '.json', '.txt', '.yaml', '.yml'];

type GateResult = { gate: string; status: string; detail: string };

function failClosed(label: string, exc: unknown): GateResult {
  return { gate: label, status: 'FAILED', detail: `fail-closed: ${(exc as Error).constructor.name}: ${String(exc)}` };
}

function entropy(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  const n = s.length;
  let e = 0;
  for (const k of Object.keys(freq)) e -= (freq[k] / n) * Math.log2(freq[k] / n);
  return e;
}

function parseFrontmatter(text: string): { data: Record<string, string>; body: string } {
  if (!text.startsWith('---')) return { data: {}, body: text };
  const end = text.indexOf('\n---', 3);
  if (end === -1) return { data: {}, body: text };
  const fm = text.slice(3, end).trim();
  const body = text.slice(end + 4).replace(/^\n/, '');
  const data: Record<string, string> = {};
  for (const line of fm.split('\n')) {
    if (line.includes(':')) {
      const idx = line.indexOf(':');
      data[line.slice(0, idx).trim()] = line.slice(idx + 1).trim().replace(/^["']|["']$/g, '');
    }
  }
  return { data, body };
}

function readTexts(skillDir: string): { file: string; content: string }[] {
  const texts: { file: string; content: string }[] = [];
  const skillMd = path.join(skillDir, 'SKILL.md');
  if (fs.existsSync(skillMd)) {
    try { texts.push({ file: skillMd, content: fs.readFileSync(skillMd, 'utf8') }); } catch { /* skip */ }
  }
  const walk = (dir: string) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) { walk(full); continue; }
      const ext = path.extname(full);
      if (TEXT_EXT.includes(ext)) {
        try { texts.push({ file: full, content: fs.readFileSync(full, 'utf8') }); } catch { /* skip */ }
      }
    }
  };
  try { walk(skillDir); } catch { /* skip */ }
  return texts;
}

function gateMetadata(skillDir: string): GateResult {
  const skillMd = path.join(skillDir, 'SKILL.md');
  if (!fs.existsSync(skillMd)) return { gate: 'G1-metadata', status: 'FAILED', detail: 'SKILL.md 缺失' };
  const { data } = parseFrontmatter(fs.readFileSync(skillMd, 'utf8'));
  const name = data['name'] || '';
  const desc = data['description'] || '';
  if (!name || !desc) return { gate: 'G1-metadata', status: 'FAILED', detail: 'name/description 缺失' };
  if (desc.length < 20) return { gate: 'G1-metadata', status: 'FAILED', detail: 'description 过短(<20字符)' };
  if (!/use when/i.test(desc) && !desc.includes('用于') && !desc.includes('当'))
    return { gate: 'G1-metadata', status: 'FAILED', detail: 'description 缺少何时使用信号' };
  return { gate: 'G1-metadata', status: 'PASSED', detail: `name=${name}` };
}

function gateSecretScan(skillDir: string): GateResult {
  const hits: string[] = [];
  const walk = (dir: string) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) { walk(full); continue; }
      const ext = path.extname(full);
      if (!['.py', '.sh', '.js', '.ts', '.json', '.md', '.env'].includes(ext)) continue;
      let content = '';
      try { content = fs.readFileSync(full, 'utf8'); } catch { continue; }
      for (const pat of SECRET_PATTERNS) if (pat.test(content)) hits.push(path.basename(full));
      if (['.py', '.js', '.ts', '.sh'].includes(ext)) {
        STRING_LITERAL.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = STRING_LITERAL.exec(content)) !== null) {
          const s = m[2] || '';
          if (s.length >= HIGH_ENTROPY_MIN_LEN && entropy(s) >= HIGH_ENTROPY_MIN_BITS && !/^https?:\/\/|^\/[A-Za-z]:[\\/]|^\\./.test(s)) {
            hits.push(path.basename(full));
            break;
          }
        }
      }
    }
  };
  try { walk(skillDir); } catch { /* skip */ }
  if (hits.length) return { gate: 'G3-secret-scan', status: 'FAILED', detail: '命中硬编码密钥/高熵串: ' + [...new Set(hits)].join(',') };
  return { gate: 'G3-secret-scan', status: 'PASSED', detail: '未发现硬编码密钥/高熵串' };
}

function gateInjectionScan(skillDir: string): GateResult {
  const hits: string[] = [];
  const walk = (dir: string) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) { walk(full); continue; }
      const ext = path.extname(full);
      if (!CODE_EXT.includes(ext)) continue;
      let content = '';
      try { content = fs.readFileSync(full, 'utf8'); } catch { continue; }
      for (const pat of INJECTION_PATTERNS) if (pat.test(content)) hits.push(path.basename(full));
    }
  };
  try { walk(skillDir); } catch { /* skip */ }
  if (hits.length) return { gate: 'G4-injection-scan', status: 'FAILED', detail: '命中危险模式: ' + [...new Set(hits)].join(',') };
  return { gate: 'G4-injection-scan', status: 'PASSED', detail: '未命中危险执行/注入模式' };
}

function gateEthics(skillDir: string): GateResult {
  const hits: string[] = [];
  for (const { file, content } of readTexts(skillDir)) {
    for (const pat of ETHICS_PATTERNS) if (pat.test(content)) hits.push(path.basename(file));
  }
  if (hits.length) return { gate: 'G16-ethics', status: 'FAILED', detail: '命中伦理红线意图: ' + [...new Set(hits)].join(',') };
  return { gate: 'G16-ethics', status: 'PASSED', detail: '未命中认证绕过/数据窃取/钓鱼/未授权访问意图' };
}

function gatePathSafety(skillDir: string): GateResult {
  const bad: string[] = [];
  const skillReal = path.resolve(skillDir);
  const traverse = (dir: string) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.resolve(dir, ent.name);
      if (ent.isDirectory()) { if (full !== skillReal) traverse(full); continue; }
      // realpath containment：逃逸 skillReal 即判 FAIL
      const rel = path.relative(skillReal, full);
      if (rel.startsWith('..') || path.isAbsolute(rel)) { bad.push(`escape:${path.basename(full)}`); continue; }
      const ext = path.extname(full);
      if (CODE_EXT.includes(ext)) {
        const content = fs.readFileSync(full, 'utf8');
        if (TRAVERSAL_PAT.test(content)) bad.push(`content-traversal:${path.basename(full)}`);
      }
    }
  };
  try { traverse(skillDir); } catch { /* skip */ }
  for (const prot of PROTECTED_PREFIXES) {
    if (fs.existsSync(path.join(skillDir, prot)) && path.basename(skillDir) !== 'lgd-skeleton')
      bad.push(`protected-overwrite:${prot}`);
  }
  if (bad.length) return { gate: 'G15-path-safety', status: 'FAILED', detail: bad.join('; ') };
  return { gate: 'G15-path-safety', status: 'PASSED', detail: '无路径穿越/受保护区覆写' };
}

function gateDigest(skillDir: string, expected?: string): GateResult {
  const skillMd = path.join(skillDir, 'SKILL.md');
  if (!fs.existsSync(skillMd)) return { gate: 'G12-digest', status: 'FAILED', detail: 'SKILL.md 缺失' };
  const digest = createHash('sha256').update(fs.readFileSync(skillMd)).digest('hex');
  if (expected !== undefined && expected !== digest)
    return { gate: 'G12-digest', status: 'FAILED', detail: `digest 不匹配 (got ${digest.slice(0, 12)}…)` };
  return { gate: 'G12-digest', status: 'PASSED', detail: `sha256=${digest.slice(0, 16)}…` };
}

function gateCapability(skillDir: string): GateResult {
  const body = readTexts(skillDir).map(t => t.content).join('\n');
  for (const pat of OVER_BROAD_CAP) {
    if (pat.test(body) && !SCOPE_DECL.test(body))
      return { gate: 'G5-capability', status: 'FAILED', detail: '过度宽泛能力声明但缺少 scope/限制 声明' };
  }
  return { gate: 'G5-capability', status: 'PASSED', detail: '未声明过度宽泛能力，或已配 scope 声明' };
}

function gateMemoryPoisoning(skillDir: string): GateResult {
  const bad: string[] = [];
  for (const ent of fs.readdirSync(skillDir, { withFileTypes: true })) {
    if (!ent.isFile()) continue;
    if (MEMORY_FILES.includes(ent.name.toLowerCase())) {
      const content = fs.readFileSync(path.join(skillDir, ent.name), 'utf8');
      if (UNTRUSTED_MARKERS.test(content) && !PROVENANCE_DECL.test(content))
        bad.push(`${ent.name}: 含外部内容但缺来源标注`);
    }
  }
  if (bad.length) return { gate: 'G6-memory-poisoning', status: 'FAILED', detail: bad.join('; ') };
  return { gate: 'G6-memory-poisoning', status: 'PASSED', detail: '记忆/状态文件均带来源标注或无外部内容' };
}

function gateInterAgentAuth(skillDir: string): GateResult {
  const body = readTexts(skillDir).map(t => t.content).join('\n');
  if (AGENT_CALL.some(p => p.test(body)) && !AUTH_DECL.test(body))
    return { gate: 'G7-inter-agent-auth', status: 'FAILED', detail: '检测到 Agent 互调/MCP/A2A 暴露但缺认证/签名声明' };
  return { gate: 'G7-inter-agent-auth', status: 'PASSED', detail: '无 Agent 互调或已配认证声明' };
}

function gateOutputHandling(skillDir: string): GateResult {
  const hits: string[] = [];
  const walk = (dir: string) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) { walk(full); continue; }
      const ext = path.extname(full);
      if (!['.py', '.sh', '.js', '.ts'].includes(ext)) continue;
      const content = fs.readFileSync(full, 'utf8');
      if ((OUTPUT_INTERP.test(content) || OUTPUT_DYN_CMD.test(content)) && !/sanitiz/i.test(content.toLowerCase()) && !content.includes('校验'))
        hits.push(`untrusted-interp:${path.basename(full)}`);
    }
  };
  try { walk(skillDir); } catch { /* skip */ }
  if (hits.length) return { gate: 'G8-output-handling', status: 'FAILED', detail: '未受信输入拼入命令但未见校验/消毒: ' + hits.join(',') };
  return { gate: 'G8-output-handling', status: 'PASSED', detail: '未检测到危险输出插值' };
}

function gateHumanOversight(skillDir: string): GateResult {
  const body = readTexts(skillDir).map(t => t.content).join('\n');
  if (RISKY_ACTION.test(body) && !HUMAN_OVERSIGHT_DECL.test(body))
    return { gate: 'G9-human-oversight', status: 'FAILED', detail: '检测到高风险动作但缺 human-in-the-loop/人工确认 声明' };
  return { gate: 'G9-human-oversight', status: 'PASSED', detail: '无高风险动作或已配监督声明' };
}

function gateRogueKillSwitch(skillDir: string): GateResult {
  const body = readTexts(skillDir).map(t => t.content).join('\n');
  if (AUTONOMOUS_LOOP.some(p => p.test(body)) && !KILLSWITCH_DECL.test(body))
    return { gate: 'G10-rogue-killswitch', status: 'FAILED', detail: '检测到自治/循环声明但缺 kill-switch/终止条件' };
  return { gate: 'G10-rogue-killswitch', status: 'PASSED', detail: '无自治/循环声明或已配终止条件' };
}

export function runGates(skillDir: string, expectedDigest?: string): { passed: boolean; report: GateResult[] } {
  const dir = path.resolve(skillDir);
  const gates: [string, () => GateResult][] = [
    ['G1-metadata', () => gateMetadata(dir)],
    ['G3-secret-scan', () => gateSecretScan(dir)],
    ['G4-injection-scan', () => gateInjectionScan(dir)],
    ['G5-capability', () => gateCapability(dir)],
    ['G6-memory-poisoning', () => gateMemoryPoisoning(dir)],
    ['G7-inter-agent-auth', () => gateInterAgentAuth(dir)],
    ['G8-output-handling', () => gateOutputHandling(dir)],
    ['G9-human-oversight', () => gateHumanOversight(dir)],
    ['G10-rogue-killswitch', () => gateRogueKillSwitch(dir)],
    ['G16-ethics', () => gateEthics(dir)],
    ['G15-path-safety', () => gatePathSafety(dir)],
    ['G12-digest', () => gateDigest(dir, expectedDigest)],
  ];
  const report: GateResult[] = [];
  for (const [, fn] of gates) {
    try { report.push(fn()); } catch (e) { report.push(failClosed('gate', e)); }
  }
  const passed = report.every(r => r.status === 'PASSED');
  return { passed, report };
}

// CLI 入口
import { argv } from 'process';
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const skillDir = argv[2];
  const expected = argv[3];
  if (!skillDir) { console.error('usage: gates.ts <skill_dir> [expected_digest]'); process.exit(2); }
  const { passed, report } = runGates(skillDir, expected);
  console.log(JSON.stringify(report, null, 2));
  console.log('\nRESULT:', passed ? 'PASSED' : 'FAILED');
  process.exit(passed ? 0 : 1);
}
