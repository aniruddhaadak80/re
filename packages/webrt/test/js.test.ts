import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beautify, deobfuscate, unpackBundle, findEndpoints, recoverSources, SourceMapIndex, decodeMappings, obfuscationScore } from '../src/index.js';

const S = join(dirname(fileURLToPath(import.meta.url)), '../../../samples/webrt');
const read = (p: string) => readFileSync(join(S, p), 'utf8');

// Strings that are in samples/webrt/obf-input.js. javascript-obfuscator hid them in a rotated rc4/base64 string array.
const KNOWN = ['https://telemetry.revlens-fixture.example/collect', 'RL-LICENSE-SALT-2026', 'invalid license key', 'tok_live_123', 'sending payload', 'enterprise', 'application/json'];

test('deobfuscate: javascript-obfuscator rc4 string array with control flow flattening', () => {
  const obf = read('obfuscated.js');
  for (const s of KNOWN) assert.ok(!obf.includes(s), `fixture should hide ${s}`);
  const d = deobfuscate(obf);
  assert.equal(d.stringArray?.encoding, 'rc4');
  assert.ok((d.stringArray?.rotated ?? 0) > 0, 'array was rotated');
  assert.ok(d.stats.stringsDecoded >= 20);
  for (const s of KNOWN) assert.ok(d.code.includes(`'${s}'`) || d.code.includes(s), `decoded ${s}`);
  assert.ok(d.code.includes('function buildRequest('));
  assert.ok(d.code.includes('function checkLicense('));
  assert.ok(d.code.includes("console.warn('invalid license key')"));
  assert.ok(d.code.includes("fetch("));
  // helpers are gone: no string array function and no rotation loop left
  assert.ok(!/parseInt\(/.test(d.code), 'rotation IIFE removed');
  assert.ok(!d.code.includes(d.stringArray!.decoderName), 'decoder removed');
  assert.ok(obfuscationScore(obf) > 0.2 && obfuscationScore(d.code) < obfuscationScore(obf));
});

test('deobfuscate: base64 encoded string array', () => {
  const d = deobfuscate(read('obfuscated-base64.js'));
  assert.equal(d.stringArray?.encoding, 'base64');
  for (const s of KNOWN) assert.ok(d.code.includes(s), `decoded ${s}`);
  // decodedStrings lists the whole array in order after rotation
  assert.ok(d.decodedStrings.includes('RL-LICENSE-SALT-2026'));
});

test('deobfuscate: switch dispatcher from control flow flattening is restored in order', () => {
  const obf = read('obfuscated-cff.js');
  assert.ok(obf.includes('switch'));
  const d = deobfuscate(obf);
  assert.equal(d.stats.switchesUnflattened, 1);
  const i1 = d.code.indexOf("'step one'"), i2 = d.code.indexOf("'step two'"), i3 = d.code.indexOf("'step three'");
  assert.ok(i1 > 0 && i1 < i2 && i2 < i3, 'statements are back in source order');
  assert.ok(!d.code.includes('switch'));
});

test('beautify decodes hex escapes and keeps behavior-neutral output', () => {
  const b = beautify("var a='\\x68\\x65\\x6c\\x6c\\x6f',b=0x10;function f(){return a+b}");
  assert.ok(b.code.includes("'hello'"));
  assert.ok(b.code.includes('16'));
  assert.ok(b.lines >= 4);
  assert.equal(b.literalsNormalized, 2);
});

// webpack writes its own chunk and module ids to stats.*.json at fixture time: that is the reference.
type Stats = { chunk: string | number; files: string[]; modules: { id: string | number; name: string }[] }[];
const stats = (f: string) => JSON.parse(read(`webpack-dist/${f}`)) as Stats;

test('bundle: webpack 5 production bundle, numeric ids named through the source map, matches webpack stats', () => {
  const code = read('webpack-dist/bundle.prod.js');
  const b = unpackBundle(code, { sourceMap: read('webpack-dist/bundle.prod.js.map') });
  assert.equal(b.bundler, 'webpack5');
  const ref = stats('stats.prod.json').find((c) => c.files.includes('bundle.prod.js'))!;
  // the entry module (./index.js) is inlined into the runtime by webpack 5, the rest live in the registry
  const expected = ref.modules.filter((m) => m.id !== '' && m.name !== './index.js').map((m) => [String(m.id), m.name.replace(/^\.\//, '')]).sort();
  const got = b.modules.map((m) => [m.id, m.path]).sort();
  assert.deepEqual(got, expected);
  assert.equal(b.modules.length, 2);
  assert.deepEqual(b.modules.find((m) => m.id === '504')?.exports.sort(), ['tE', 'wz']);
  assert.ok(b.entryIds.includes('504') && b.entryIds.includes('214'));
  assert.equal(b.runtime.publicPath, '/');
  assert.equal(b.sourceMappingURL, 'bundle.prod.js.map');
});

test('bundle: webpack 5 development bundle keeps paths as keys', () => {
  const b = unpackBundle(read('webpack-dist/bundle.dev.js'), { includeCode: true });
  assert.equal(b.bundler, 'webpack5');
  const ref = stats('stats.dev.json').find((c) => c.files.includes('bundle.dev.js'))!;
  const expected = ref.modules.filter((m) => m.id !== '' && m.name !== './index.js').map((m) => String(m.id)).sort();
  assert.deepEqual(b.modules.map((m) => m.id).sort(), expected);
  const api = b.modules.find((m) => m.id === './api.js')!;
  assert.equal(api.path, 'api.js');
  assert.deepEqual(api.exports.sort(), ['API_BASE', 'getUser', 'openLive', 'saveSettings']);
  assert.ok(api.code?.includes('XMLHttpRequest'));
});

test('bundle: jsonp chunks (prod numeric and dev named) match webpack stats', () => {
  for (const [file, statsFile] of [['chunk.100.prod.js', 'stats.prod.json'], ['chunk.dashboard_js.dev.js', 'stats.dev.json']] as const) {
    const code = read(`webpack-dist/${file}`);
    let map: string | undefined;
    try { map = read(`webpack-dist/${file}.map`); } catch { /* dev has none */ }
    const b = unpackBundle(code, { sourceMap: map });
    const ref = stats(statsFile).find((c) => c.files.includes(file))!;
    assert.equal(b.bundler, 'webpack-chunk');
    assert.deepEqual(b.chunkIds, [String(ref.chunk)]);
    assert.deepEqual(b.modules.map((m) => m.id), ref.modules.map((m) => String(m.id)));
    assert.equal(b.modules[0]?.path, 'dashboard.js');
    assert.deepEqual(b.modules[0]?.exports, ['renderDashboard']);
  }
});

test('bundle: esbuild __commonJS and browserify shapes', () => {
  const esb = `var __commonJS = (cb, mod) => function __require() { return mod || (0, cb[Object.keys(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports; };
var require_util = __commonJS({ "src/util.js"(exports, module) { module.exports = { add: (a, b) => a + b }; } });
var require_main = __commonJS({ "src/main.js"(exports) { var util = require_util(); fetch("/api/v1/items"); } });
require_main();`;
  const e = unpackBundle(esb);
  assert.equal(e.bundler, 'esbuild');
  assert.deepEqual(e.modules.map((m) => m.path).sort(), ['src/main.js', 'src/util.js']);
  const bfy = `(function(){function r(e,n,t){return e}return r})()({1:[function(require,module,exports){var b=require('./b');console.log(b)},{"./b":2}],2:[function(require,module,exports){module.exports='b'},{}]},{},[1]);`;
  const b = unpackBundle(bfy);
  assert.equal(b.bundler, 'browserify');
  assert.deepEqual(b.entryIds, ['1']);
  assert.equal(b.modules.find((m) => m.id === '2')?.path, 'b');
  assert.deepEqual(b.modules.find((m) => m.id === '1')?.deps, ['2']);
});

test('endpoints: fetch, XHR, WebSocket, sendBeacon, env names and feature flags from the real webpack build', () => {
  const r = findEndpoints(read('webpack-dist/bundle.dev.js'));
  const calls = r.calls.map((c) => [c.api, c.method, c.url].filter(Boolean).join(' '));
  assert.ok(calls.includes('fetch GET https://api.revlens-fixture.example/v2/users/${}'), calls.join('\n'));
  assert.ok(calls.includes('XMLHttpRequest.open POST /api/settings'));
  assert.ok(calls.includes('new WebSocket wss://live.revlens-fixture.example/socket'));
  assert.deepEqual(r.hosts, ['api.revlens-fixture.example', 'live.revlens-fixture.example']);
  assert.deepEqual(r.envNames, ['DEBUG_MODE']);
  assert.deepEqual(r.featureFlags.map((f) => f.name), ['new-dashboard']);
  const chunk = findEndpoints(read('webpack-dist/chunk.100.prod.js'));
  assert.deepEqual(chunk.calls.map((c) => [c.api, c.url]), [['navigator.sendBeacon', '/telemetry/dashboard-open']]);
  const dyn = findEndpoints('eval("1+1"); new Function("a", "return a"); setTimeout("alert(1)", 10); x.postMessage(1); addEventListener("message", f)');
  assert.deepEqual(dyn.dynamicCode.map((d) => d.api), ['eval', 'new Function', 'setTimeout(string)']);
  assert.equal(dyn.postMessage.length, 1);
  assert.equal(dyn.messageListeners.length, 1);
});

test('source map recovery rebuilds the original webpack sources byte for byte', () => {
  const r = recoverSources(read('webpack-dist/bundle.prod.js.map'), { includeContent: true });
  const app = r.files.filter((f) => !f.path.startsWith('webpack/'));
  assert.deepEqual(app.map((f) => f.path).sort(), ['api.js', 'index.js', 'util/format.js']);
  for (const f of app) assert.equal(f.content, read(`webpack-src/${f.path}`), `${f.path} matches the original`);
  assert.equal(r.coverage, 100);
  assert.ok(r.mappings > 100);
  // every recovered path is relative and safe
  for (const f of r.files) assert.ok(!f.path.startsWith('/') && !f.path.includes('..'));
});

test('source map lookup maps generated positions back to original files', () => {
  const code = read('webpack-dist/bundle.prod.js');
  const idx = new SourceMapIndex(read('webpack-dist/bundle.prod.js.map'));
  const at = code.indexOf('https://api.revlens-fixture.example');
  const pos = idx.originalPositionFor(1, at);
  assert.equal(pos.source, 'webpack:///./api.js');
  assert.equal(pos.line, 1);
  const ms = decodeMappings('AAAA,SAASA;AACA');
  assert.deepEqual(ms.map((m) => [m.genLine, m.genCol, m.source, m.origLine, m.origCol]), [[0, 0, 0, 0, 0], [0, 9, 0, 0, 9], [1, 0, 0, 1, 9]]);
  assert.equal(readdirSync(join(S, 'webpack-dist')).filter((f) => f.endsWith('.map')).length, 2);
});
