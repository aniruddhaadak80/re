// Parser tests against real tool output recorded from samples/bridges fixtures
// (radare2 6.2.6 with r2ghidra, GNU objdump 2.44, gdb 16.3, lldb 19.1.7, binwalk 2.4.3, frida-tools 17.26.2, ilspycmd 9.1).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  parseR2Functions, parseR2Disasm, parseR2Decompile, parseR2Xrefs, parseR2Strings, parseR2Imports, parseR2Info,
  parseObjdumpDisasm, parseObjdumpSections, parseObjdumpSymbols, parseGdbBatch, parseLldbBatch, parseBinwalkTable, parseBinwalkJson,
  parseFridaPs, parseFridaDevices, parseFridaOutput, parseAdbDevices, parseAdbPackages, parseAdbPmPath, parseGhidraExport,
  extractJson, page, buildHookScript, HOOK_TEMPLATES, TOOL_META, TOOL_IDS, installFor,
} from '../src/index.ts';
import { parseIlspyTypes } from '../src/providers/jvm.ts';
import { parseVersion, javaMajor } from '../src/detect.ts';

const here = dirname(fileURLToPath(import.meta.url));
const rec = (f: string) => readFileSync(join(here, '..', '..', '..', 'samples', 'bridges', 'recorded', f), 'utf8');

test('r2 aflj: add_numbers at 0x828 size 32, check_password at 0x848 size 128', () => {
  const fns = parseR2Functions(rec('r2-aflj.json'));
  const add = fns.find((f) => f.name === 'sym.add_numbers');
  const chk = fns.find((f) => f.name === 'sym.check_password');
  assert.deepEqual([add?.address, add?.size], ['0x828', 32]);
  assert.deepEqual([chk?.address, chk?.size], ['0x848', 128]);
  assert.ok(fns.some((f) => f.name === 'main'));
  // sorted by address
  for (let i = 1; i < fns.length; i++) assert.ok(parseInt(fns[i - 1]!.address, 16) <= parseInt(fns[i]!.address, 16));
});

test('r2 axtj: check_password is called from main at 0x98c', () => {
  const x = parseR2Xrefs(rec('r2-axtj-check_password.json'));
  assert.equal(x.length, 1);
  assert.deepEqual(x[0], { from: '0x98c', type: 'CALL', opcode: 'bl sym.check_password', function: 'main', functionAddress: '0x944' });
});

test('r2 pdfj and objdump -d agree on add_numbers addresses and bytes', () => {
  const r2 = parseR2Disasm(rec('r2-pdfj-add_numbers.json'));
  assert.equal(r2.address, '0x828');
  assert.equal(r2.size, 32);
  const od = parseObjdumpDisasm(rec('objdump-d.txt'));
  assert.equal(od.format, 'elf64-littleaarch64');
  const f = od.functions.find((x) => x.name === 'add_numbers')!;
  assert.equal(f.address, '0x828');
  assert.equal(f.instructions.length, r2.instructions.length);
  r2.instructions.forEach((ins, i) => {
    const o = f.instructions[i]!;
    assert.equal(o.address, ins.address);
    // r2 prints bytes in file order, objdump prints the 32 bit word: reverse r2's bytes to compare.
    const le = ins.bytes!.match(/../g)!.reverse().join('');
    assert.equal(o.bytes, le);
  });
  assert.equal(f.instructions[0]!.text, 'sub sp, sp, #0x10');
  const main = od.functions.find((x) => x.name === 'main')!;
  assert.ok(main.instructions.some((i) => i.address === '0x98c' && i.text.startsWith('bl 848 <check_password>')));
});

test('r2 pdgj: r2ghidra C for check_password calls strlen and strcmp', () => {
  const c = parseR2Decompile(rec('r2-pdgj-check_password.json'))!;
  assert.match(c, /check_password/);
  assert.match(c, /strlen/);
  assert.match(c, /strcmp/);
  assert.equal(parseR2Decompile('{"code":"   "}'), undefined);
});

test('r2 izj, iij and ij', () => {
  const s = parseR2Strings(rec('r2-izj.json'));
  assert.deepEqual(s[0], { value: 'revlens-open-sesame', vaddr: '0xa08', paddr: '0xa08', length: 19, size: 20, type: 'ascii', section: '.rodata' });
  const im = parseR2Imports(rec('r2-iij.json'));
  assert.ok(im.some((i) => i.name === 'strcmp'));
  assert.equal(im.find((i) => i.name === 'strlen')?.plt, '0x680');
  const info = parseR2Info(rec('r2-ij.json'));
  assert.equal(info.arch, 'arm');
  assert.equal(info.bits, 64);
  assert.equal(info.machine, 'ARM aarch64');
  assert.equal(info.pic, true);
  assert.equal(info.nx, true);
  assert.equal(info.stripped, false);
});

test('objdump -h and -t', () => {
  const secs = parseObjdumpSections(rec('objdump-h.txt'));
  const text = secs.find((s) => s.name === '.text')!;
  assert.deepEqual([text.vma, text.size, text.fileOffset, text.align], ['0x700', 0x2e4, '0x700', 64]);
  assert.ok(text.flags.includes('CODE'));
  const syms = parseObjdumpSymbols(rec('objdump-t.txt'));
  const add = syms.find((s) => s.name === 'add_numbers')!;
  assert.deepEqual([add.address, add.size, add.section], ['0x828', 32, '.text']);
  assert.ok(syms.some((s) => s.name === 'strcmp' && s.version?.startsWith('GLIBC')));
});

test('gdb batch on the static binary: x0=2 x1=41 at add_numbers, backtrace into main', () => {
  const s = parseGdbBatch(rec('gdb-batch-static-aarch64.txt'));
  assert.equal(s.stops.length, 2);
  const a = s.stops[0]!;
  assert.equal(a.reason, 'breakpoint 1');
  assert.equal(a.function, 'add_numbers');
  assert.equal(a.registers.x0, '0x2');
  assert.equal(a.registers.x1, '0x29');
  assert.deepEqual(a.backtrace.map((f) => f.function), ['add_numbers', 'main']);
  assert.equal(a.memory.length, 2);
  assert.equal(a.memory[0]!.values.length, 8);
  assert.equal(s.stops[1]!.function, 'check_password');
  assert.equal(s.exitCode, 1);
});

test('lldb batch on the static binary: same registers as gdb', () => {
  const s = parseLldbBatch(rec('lldb-batch-static-aarch64.txt'));
  assert.equal(s.stops.length, 2);
  const a = s.stops[0]!;
  assert.equal(a.reason, 'breakpoint 1.1');
  assert.equal(a.function, 'add_numbers');
  assert.equal(parseInt(a.registers.x0!, 16), 2);
  assert.equal(parseInt(a.registers.x1!, 16), 41);
  assert.deepEqual(a.backtrace.map((f) => f.function).slice(0, 2), ['add_numbers', 'main']);
  assert.equal(a.memory.length, 2);
  assert.equal(s.stops[1]!.function, 'check_password');
  assert.equal(s.exitCode, 1);
});

test('binwalk v2 finds the planted files at their offsets', () => {
  const h = parseBinwalkTable(rec('binwalk-v2.txt'));
  assert.deepEqual(h.map((x) => [x.offset, x.name]), [
    [256, 'gzip compressed data'], [1024, 'zip archive data'], [1164, 'end of zip archive'], [2048, 'png image'], [2089, 'zlib compressed data'],
  ]);
  assert.match(h[1]!.description, /etc\/passwd\.sample/);
});

test('binwalk v3 JSON log shape', () => {
  const j = JSON.stringify([{ Analysis: { file_path: 'x', file_map: [{ offset: 1024, id: 'a', size: 40, name: 'zip', confidence: 250, description: 'ZIP archive' }, { offset: 256, name: 'gzip', description: 'gzip' }] } }]);
  const h = parseBinwalkJson(j);
  assert.deepEqual(h.map((x) => [x.offset, x.name, x.size]), [[256, 'gzip', undefined], [1024, 'zip', 40]]);
});

test('frida-ps --json and frida-ls-devices', () => {
  const p = parseFridaPs(rec('frida-ps.json'));
  assert.equal(p.length, 7);
  assert.ok(p.some((x) => x.name === 'npm install' && x.pid === 9420));
  const d = parseFridaDevices(rec('frida-ls-devices.txt'));
  assert.deepEqual(d[0], { id: 'local', type: 'local', name: 'Local System', os: 'Debian GNU/Linux 13' });
  assert.deepEqual(d[1], { id: 'barebone', type: 'remote', name: 'GDB Remote Stub' });
  assert.equal(d.length, 3);
});

test('frida output split into events, logs and errors', () => {
  const r = parseFridaOutput('@@revlens {"type":"call","t":3}\nhello\nFailed to attach: nope\n@@revlens not json\n');
  assert.deepEqual(r.events, [{ type: 'call', t: 3 }]);
  assert.deepEqual(r.errors, ['Failed to attach: nope']);
  assert.equal(r.logs.length, 2);
});

test('adb parsers', () => {
  assert.deepEqual(parseAdbDevices(rec('adb-devices-empty.txt')), []);
  const d = parseAdbDevices('List of devices attached\nemulator-5554          device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a transport_id:1\nR58M  unauthorized usb:1-1 transport_id:2\n');
  assert.deepEqual(d[0], { serial: 'emulator-5554', state: 'device', product: 'sdk_gphone64_arm64', model: 'sdk_gphone64_arm64', device: 'emu64a', transportId: '1' });
  assert.equal(d[1]!.state, 'unauthorized');
  const p = parseAdbPackages('package:/data/app/~~x==/com.example.app-1/base.apk=com.example.app\npackage:com.android.shell\npackage:bad name\n');
  assert.deepEqual(p, [{ name: 'com.example.app', apkPath: '/data/app/~~x==/com.example.app-1/base.apk' }, { name: 'com.android.shell' }]);
  assert.deepEqual(parseAdbPmPath('package:/data/app/a/base.apk\npackage:/data/app/a/split_config.arm64_v8a.apk\npackage:/data/../etc/x.apk\n'),
    ['/data/app/a/base.apk', '/data/app/a/split_config.arm64_v8a.apk']);
});

test('ilspycmd -l type list', () => {
  assert.deepEqual(parseIlspyTypes(rec('ilspy-l.txt')), [{ kind: 'class', name: 'RevLens.Samples.Greeter' }]);
});

test('ghidra export JSON validation', () => {
  const g = parseGhidraExport(JSON.stringify({ schema: 'revlens/ghidra-export@1', program: 'p', mode: 'functions', imageBase: '0x100000',
    functions: [{ name: 'add_numbers', address: '0x00100828', size: 32 }, { name: 'bad', address: 'zz' }] }))!;
  assert.deepEqual(g.functions, [{ name: 'add_numbers', address: '0x100828', size: 32 }]);
  assert.equal(parseGhidraExport('{"schema":"other"}'), undefined);
});

test('version parsing from real banners', () => {
  assert.equal(parseVersion('radare2', 'radare2 6.2.6 +1 abi:174 @ linux-arm_64'), '6.2.6');
  assert.equal(parseVersion('gdb', 'GNU gdb (Debian 16.3-1) 16.3'), '16.3');
  assert.equal(parseVersion('lldb', 'lldb version 19.1.7'), '19.1.7');
  assert.equal(parseVersion('objdump', 'GNU objdump (GNU Binutils for Debian) 2.44'), '2.44');
  assert.equal(parseVersion('binwalk', '\nBinwalk v2.4.3\nOriginal author'), '2.4.3');
  assert.equal(parseVersion('adb', 'Android Debug Bridge version 1.0.41'), '1.0.41');
  assert.equal(parseVersion('java', 'openjdk version "25.0.5" 2026-10-20 LTS'), '25.0.5');
  assert.equal(javaMajor('25.0.5'), 25);
  assert.equal(javaMajor('1.8.0_402'), 8);
});

test('extractJson tolerates banners and page() pages', () => {
  assert.deepEqual(extractJson('WARN something\n[1,2]'), [1, 2]);
  assert.equal(extractJson('nothing'), undefined);
  assert.deepEqual(page([1, 2, 3, 4], 1, 2), { items: [2, 3], total: 4, offset: 1, limit: 2, more: true });
});

test('catalog has install info for every tool on every OS and hook templates build', () => {
  for (const id of TOOL_IDS) {
    for (const os of ['linux', 'darwin', 'win32'] as const) {
      const i = installFor(id, os);
      assert.ok(i.homepage.startsWith('https://'), id);
      assert.ok(Object.keys(i).length > 1, `${id} ${os}`);
    }
    assert.ok(TOOL_META[id].description.length > 10);
  }
  for (const t of HOOK_TEMPLATES) {
    const params = t.id === 'trace-native-export' ? { export: 'open' } : t.id === 'java-method-log' ? { className: 'a.B', method: 'c' } : {};
    const s = buildHookScript(t.id, params);
    assert.match(s, /@@revlens /);
  }
});
