// Inside a Node single executable application there are no node_modules on disk, so the WebAssembly
// files of the disassemblers (iced-x86 and Capstone) are embedded as SEA assets. This patch answers
// reads of those two file names from the embedded copies; every other read goes to the file system.
'use strict';
let sea;
try { sea = require('node:sea'); } catch { sea = undefined; }
if (sea && sea.isSea && sea.isSea()) {
  const fs = require('node:fs');
  const path = require('node:path');
  const NAMES = new Set(['iced_x86_bg.wasm', 'capstone.wasm']);
  const cache = new Map();
  const embedded = (p) => {
    if (typeof p !== 'string' && !(p instanceof URL)) return undefined;
    const s = p instanceof URL ? p.pathname : p;
    const name = path.basename(s);
    if (!NAMES.has(name)) return undefined;
    if (fs.existsSync(s)) return undefined;
    if (!cache.has(name)) cache.set(name, Buffer.from(sea.getAsset(name)));
    return cache.get(name);
  };
  const readFileSync = fs.readFileSync;
  fs.readFileSync = function (p, ...rest) {
    const b = embedded(p);
    if (!b) return readFileSync.call(this, p, ...rest);
    const enc = typeof rest[0] === 'string' ? rest[0] : rest[0] && rest[0].encoding;
    return enc ? b.toString(enc) : Buffer.from(b);
  };
  const readFile = fs.readFile;
  fs.readFile = function (p, ...rest) {
    const b = embedded(p);
    if (!b) return readFile.call(this, p, ...rest);
    const cb = rest[rest.length - 1];
    process.nextTick(() => cb(null, Buffer.from(b)));
  };
  const promisesRead = fs.promises.readFile;
  fs.promises.readFile = function (p, ...rest) {
    const b = embedded(p);
    return b ? Promise.resolve(Buffer.from(b)) : promisesRead.call(this, p, ...rest);
  };
}
