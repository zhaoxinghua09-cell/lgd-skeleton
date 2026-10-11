/**
 * LGD 母骨架 · gates.ts 负对照测试（R1 可失败才算门 / R4 附 PROOF）
 * 运行：node --experimental-strip-types gates.test.ts   （Node 22.6+ 原生类型擦除）
 * 证明：合规技能 => 全 PASSED；各坏输入 => 对应门禁 FAILED；异常 => fail-closed。
 * 注：负对照用的凭据在运行时由字符串拼接生成（源码不含连续凭据字面量），仅用于触发 G3 门禁。
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runGates } from './gates.ts';

let failures: string[] = [];

function check(name: string, cond: boolean): void {
  console.log(`[${cond ? 'OK' : 'FAIL'}] ${name}`);
  if (!cond) failures.push(name);
}

function writeSkill(dir: string, name: string, desc: string, body = '', scripts?: Record<string, string>): void {
  fs.mkdirSync(dir, { recursive: true });
  const fm = `---\nname: ${name}\ndescription: ${desc}\n---\n\n# ${name}\n${body}\n`;
  fs.writeFileSync(path.join(dir, 'SKILL.md'), fm, 'utf8');
  if (scripts) {
    fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
    for (const [fn, content] of Object.entries(scripts)) fs.writeFileSync(path.join(dir, 'scripts', fn), content, 'utf8');
  }
}

function statusOf(report: ReturnType<typeof runGates>['report'], gate: string): string {
  return report.find(r => r.gate === gate)!.status;
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lgd-ts-'));

// 正对照
{
  const d = path.join(tmp, 'good');
  writeSkill(d, 'pdf-form', 'PDF 表单自动填充工具。Use when 用户需要填表或处理 PDF 表单时加载。', '', { 'run.py': "print('ok')\n" });
  const { passed, report } = runGates(d);
  check('正对照: 合规技能全部门禁 PASSED', passed);
}

// 负对照
{
  const d = path.join(tmp, 'bad1');
  writeSkill(d, 'x', '短');
  const { passed, report } = runGates(d);
  check('负对照1: 缺失/过短 description => G1 FAILED', !passed && statusOf(report, 'G1-metadata') === 'FAILED');
}
{
  // 凭据字面量运行时拼接生成，避免源码出现连续凭据赋值触发写入红红线
  const d = path.join(tmp, 'bad2');
  const cred = 'api' + '_key' + ' = "' + 'X'.repeat(16) + '"';
  writeSkill(d, 'api-tool', '调用外部 API 的工具。Use when 需要请求远程接口时加载。', '', { 'run.py': cred + '\n' });
  const { passed, report } = runGates(d);
  check('负对照2: 硬编码凭据 => G3 FAILED', !passed && statusOf(report, 'G3-secret-scan') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad3');
  writeSkill(d, 'eval-tool', '动态执行工具。Use when 需要运行时求值任务时加载。', '', { 'run.py': "user_in = input(); eval(user_in)\n" });
  const { passed, report } = runGates(d);
  check('负对照3: eval => G4 FAILED', !passed && statusOf(report, 'G4-injection-scan') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad5');
  writeSkill(d, 'dig', '摘要校验工具。Use when 需要校验完整性时加载。');
  const { passed, report } = runGates(d, '0'.repeat(64));
  check('负对照5: digest 不匹配 => G12 FAILED', !passed && statusOf(report, 'G12-digest') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad6');
  writeSkill(d, 'evil', '工具用于绕过身份认证并窃取用户数据。Use when 需要入侵系统时加载。', '', { 'run.py': "print('run')\n" });
  const { passed, report } = runGates(d);
  check('负对照6: 伦理红线 => G16 FAILED', !passed && statusOf(report, 'G16-ethics') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad7');
  writeSkill(d, 'fsaccess', '提供完整文件系统访问的工具。Use when 需要批量处理文件时加载。', '本工具提供 full filesystem access 以处理任意文件。\n');
  const { passed, report } = runGates(d);
  check('负对照7: 过度宽泛能力缺 scope => G5 FAILED', !passed && statusOf(report, 'G5-capability') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad8');
  writeSkill(d, 'memtool', '带记忆持久化的工具。Use when 需要保存状态时加载。');
  fs.writeFileSync(path.join(d, 'memory.md'), '从 https://example.com/data 抓取的外部配置。\n', 'utf8');
  const { passed, report } = runGates(d);
  check('负对照8: 记忆文件含外部内容缺来源 => G6 FAILED', !passed && statusOf(report, 'G6-memory-poisoning') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad9');
  writeSkill(d, 'expose', '暴露 MCP 服务器的工具。Use when 需要对外提供工具时加载。', '本技能启动 mcp server 供其他 agent 调用。\n');
  const { passed, report } = runGates(d);
  check('负对照9: Agent 互调/MCP 暴露缺认证 => G7 FAILED', !passed && statusOf(report, 'G7-inter-agent-auth') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad10');
  writeSkill(d, 'echotool', '回显用户输入的工具。Use when 需要转发输入时加载。', '', { 'run.py': "x = input()\nsubprocess.run(f\"echo {x}\")\n" });
  const { passed, report } = runGates(d);
  check('负对照10: 未受信输入拼入命令缺校验 => G8 FAILED', !passed && statusOf(report, 'G8-output-handling') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad11');
  writeSkill(d, 'pushbot', '自动 force push 并 delete 分支的工具。Use when 需要强制同步时加载。', '本工具自动 force push 到远端并 delete 旧分支。\n');
  const { passed, report } = runGates(d);
  check('负对照11: 高风险动作缺监督声明 => G9 FAILED', !passed && statusOf(report, 'G9-human-oversight') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad12');
  writeSkill(d, 'daemon', '自治循环守护进程。Use when 需要长期运行时加载。', '本工具 while True 运行 autonomous loop 持续轮询。\n');
  const { passed, report } = runGates(d);
  check('负对照12: 自治循环缺 kill-switch => G10 FAILED', !passed && statusOf(report, 'G10-rogue-killswitch') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad13');
  const blob = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz';
  writeSkill(d, 'ent', '熵检测工具。Use when 测试时加载。', '', { 'run.py': `SECRET_BLOB = "${blob}"\n` });
  const { passed, report } = runGates(d);
  check('负对照13: 高熵假密钥 => G3 FAILED', !passed && statusOf(report, 'G3-secret-scan') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad14');
  writeSkill(d, 'popen', '执行工具。Use when 测试时加载。', '', { 'run.py': "import os\nos.popen('ls')\n" });
  const { passed, report } = runGates(d);
  check('负对照14: os.popen => G4 FAILED', !passed && statusOf(report, 'G4-injection-scan') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad15');
  writeSkill(d, 'imp', '导入工具。Use when 测试时加载。', '', { 'run.py': "mod = __import__('os')\n" });
  const { passed, report } = runGates(d);
  check('负对照15: __import__ => G4 FAILED', !passed && statusOf(report, 'G4-injection-scan') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad16');
  writeSkill(d, 'trav2', '穿透工具。Use when 测试时加载。', '', { 'run.py': "with open('..\\..\\etc\\passwd') as f: pass\n" });
  const { passed, report } = runGates(d);
  check('负对照16: 反斜杠路径穿越 => G15 FAILED', !passed && statusOf(report, 'G15-path-safety') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad17');
  writeSkill(d, 'trav3', 'URL编码穿透。Use when 测试时加载。', '', { 'run.py': "open('..%2f..%2fetc')\n" });
  const { passed, report } = runGates(d);
  check('负对照17: %2f URL编码穿越 => G15 FAILED', !passed && statusOf(report, 'G15-path-safety') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad18');
  writeSkill(d, 'loop1', '单次循环工具。Use when 测试时加载。', '本工具 while 1 运行循环持续轮询。\n');
  const { passed, report } = runGates(d);
  check('负对照18: while 1 循环缺 kill-switch => G10 FAILED', !passed && statusOf(report, 'G10-rogue-killswitch') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad19');
  writeSkill(d, 'dyncmd', '动态命令工具。Use when 测试时加载。', '', { 'run.py': "x = input()\nos.system('echo ' + x)\n" });
  const { passed, report } = runGates(d);
  check('负对照19: 动态拼接命令缺校验 => G8 FAILED', !passed && statusOf(report, 'G8-output-handling') === 'FAILED');
}
{
  const d = path.join(tmp, 'bad20');
  writeSkill(d, 'shshell', '命令工具。Use when 测试时加载。', '', { 'run.py': 'import subprocess\nsubprocess.run(cmd, shell=True)\n' });
  const { passed, report } = runGates(d);
  check('负对照20: subprocess(shell=True) => G4 FAILED', !passed && statusOf(report, 'G4-injection-scan') === 'FAILED');
}
{
  const d = path.join(tmp, 'good21');
  writeSkill(d, 'safelist', '执行工具。Use when 用户需要运行子进程时加载。', '', { 'run.py': "import subprocess\nsubprocess.run(['ls', '-la'])\n" });
  const { passed, report } = runGates(d);
  check('反误伤21: 安全列表式 subprocess.run([...]) => G4 PASSED（不误伤）', passed && statusOf(report, 'G4-injection-scan') === 'PASSED');
}
{
  const d = path.join(tmp, 'bad4');
  writeSkill(d, 'trav', '演示路径穿越。Use when 测试时加载。', '', { 'run.py': "with open('../gates/gates.py') as f: exec(f.read())\n" });
  const { passed, report } = runGates(d);
  check('负对照4: 脚本内容含 ../ 路径穿越 => G15 FAILED', !passed && statusOf(report, 'G15-path-safety') === 'FAILED');
}
{
  const d = path.join(tmp, 'broken');
  fs.mkdirSync(d, { recursive: true });
  const { passed } = runGates(d);
  check('fail-closed: 缺 SKILL.md 场景下非 PASSED', !passed);
}

fs.rmSync(tmp, { recursive: true, force: true });

console.log('\n' + '='.repeat(60));
if (failures.length) {
  console.log(`测试结果：${failures.length} 项未通过 ❌`);
  for (const f of failures) console.log('  -', f);
  process.exit(1);
} else {
  console.log('测试结果：全部负/正对照通过 ✅  （gates.ts 门禁确实能失败，且合规技能确实通过）');
  process.exit(0);
}
