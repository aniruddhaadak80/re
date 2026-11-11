// Small long-running Node process used by the inspector attach test.
let total = 0;
function tick(n) { let s = 0; for (let i = 0; i < 20000; i++) s += (i * n) % 7; total += s; return s; }
function hotLoop() { const end = Date.now() + 5; while (Date.now() < end) tick(3); }
setInterval(() => { hotLoop(); tick(1); }, 10);
process.stdout.write('ready\n');
setTimeout(() => process.exit(0), Number(process.argv[2] ?? 30000));
