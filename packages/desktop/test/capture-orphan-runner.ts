// Child script for the "capture lets go of leftover pipes" test. It captures a command whose own
// child starts a new session (so the group signal cannot reach it) and keeps the inherited stdout
// pipe open for 30 s. The capture must return and this process must then exit on its own.
import { captureProcess } from '../src/node.js';
const prog = `const { spawn } = require('node:child_process');
const g = spawn(process.execPath, ['-e', 'setTimeout(()=>{}, 30000)'], { stdio: ['ignore', 'inherit', 'inherit'], detached: true });
g.unref(); console.log(JSON.stringify({ grandchild: g.pid })); setTimeout(() => {}, 60000);`;
const t0 = Date.now();
const r = await captureProcess({ allowExecution: true, command: [process.execPath, '-e', prog], durationMs: 1200, strace: false });
const gc = JSON.parse(r.capture.stdout!.excerpt.trim().split('\n')[0]!).grandchild as number;
process.stdout.write(JSON.stringify({ returnedMs: Date.now() - t0, grandchild: gc }) + '\n');
// the grandchild is cleaned up by the test after this process is gone
