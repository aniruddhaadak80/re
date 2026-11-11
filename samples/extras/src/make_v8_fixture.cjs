// Writes add.jsc: real V8 code cache from vm.Script#createCachedData, plus its facts.
const vm = require('vm'), fs = require('fs'), path = require('path');
const dir = path.join(__dirname, '..');
const src = 'function add(a, b) { return a + b }\nmodule.exports = add;\n';
const s = new vm.Script(src, { filename: 'add.js' });
const c = s.createCachedData();
fs.writeFileSync(path.join(dir, 'add.jsc'), c);
// prove the cache is accepted by the same V8 build
const again = new vm.Script(src, { filename: 'add.js', cachedData: c });
fs.writeFileSync(path.join(dir, 'add.jsc.json'), JSON.stringify({ node: process.version, v8: process.versions.v8, length: c.length, sourceLength: src.length, cachedDataRejected: again.cachedDataRejected }, null, 1) + '\n');
