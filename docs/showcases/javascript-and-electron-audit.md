---
title: "Showcase: deobfuscate JavaScript and audit an Electron app"
description: Recover the hidden strings of javascript-obfuscator output, list its network calls, and review an Electron ASAR for risky settings.
order: 4
---

# Showcase: deobfuscate JavaScript and audit an Electron app

`samples/webrt/obfuscated.js` is javascript-obfuscator output with a string array. `samples/webrt/electron/app.asar` is a small Electron app archive.

## 1. Deobfuscate

```console
$ revlens js-deobfuscate samples/webrt/obfuscated.js
// RevLens deobfuscate: 32 strings decoded from _0x1b40 (rc4, rotated 10), 13 proxies inlined, 13 helpers removed
function buildRequest(_0x53f60b, _0x29ff15) {
  const _0x4caffd = 'https://telemetry.revlens-fixture.example/collect',
    _0x468c91 = {
      Authorization: 'Bearer ' + _0x29ff15,
      'Content-Type': 'application/json'
    };
  const _0x1e3cf9 = {
    id: _0x53f60b.id,
    name: _0x53f60b.name,
    plan: 'enterprise'
  };
  let _0x1db62f = 0;
  _0x1db62f += 1;
  const _0x5206ad = JSON.stringify(_0x1e3cf9);
  console.log('sending payload', _0x1db62f);
  return fetch(_0x4caffd, {
    method: 'POST',
    headers: _0x468c91,
    body: _0x5206ad
  });
}
function checkLicense(_0x514b49) {
  const _0x55200c = 'RL-LICENSE-SALT-2026',
    _0x5dc961 = _0x514b49.startsWith('RL-') && _0x514b49.length === 20;
  if (!_0x5dc961) return console.warn('invalid license key'), false;
  return _0x55200c.length > 0;
}
buildRequest({
  id: 7,
  name: 'ada'
}, 'tok_live_123');
checkLicense('RL-ABCDEFGHIJKLMNOPQ');
```

The string array is decoded by a small evaluator over literals. The input code is never run.

## 2. Network calls

```console
$ revlens js-endpoints samples/webrt/obfuscated.js
hosts: -
env: -
flags: -
dynamic code: -
```


## 3. Electron security review

```console
$ revlens electron-audit samples/webrt/electron/app.asar
Electron 33.2.1 (package.json), 2 files scanned, 2 windows, 3 IPC handlers
  [medium] shell.openExternal called with a non-constant URL (main.js line 21)
  [medium] shell.openExternal called with a non-constant URL (main.js line 32)
  [high] Preload exposes a raw Node or IPC object as window.fixtureApi (preload.js line 3)
  [critical] nodeIntegration enabled in BrowserWindow that loads remote content (main.js line 7: new BrowserWindow({"nodeIntegration":true,"contextIs)
  [high] contextIsolation disabled (main.js line 7: new BrowserWindow({"nodeIntegration":true,"contextIs)
  [medium] Renderer sandbox disabled (main.js line 7: new BrowserWindow({"nodeIntegration":true,"contextIs)
  [high] webSecurity disabled (main.js line 7: new BrowserWindow({"nodeIntegration":true,"contextIs)
  [medium] Deprecated remote module enabled (main.js line 7: new BrowserWindow({"nodeIntegration":true,"contextIs)
  [info] 3 IPC handlers in the main process (main.js line 31: handle('read-file'))
```


## 4. What is inside the archive

```console
$ revlens asar-list samples/webrt/electron/app.asar
4 files, 1 dirs, 1 unpacked, header 1032 B
  -       1493      0x410 main.js
  d          0            native
  u         31            native/addon.node
  -        265      0x9e5 package.json
  -        292      0xaee preload.js
```

