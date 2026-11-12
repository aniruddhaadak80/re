// Short-lived Node program for the process capture tests. It writes a marker file, connects to a
// TCP server it starts, starts one child process, holds everything open for a moment, then prints
// one JSON line with what it did and exits 7. The capture must find each of these.
import { writeFileSync, openSync, mkdtempSync } from 'node:fs';
import { createServer, connect } from 'node:net';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const dir = mkdtempSync(join(tmpdir(), 'rl-cap-'));
const marker = join(dir, 'capture-marker.txt');
writeFileSync(marker, 'revlens');
const fd = openSync(marker, 'r');
const server = createServer((s) => s.on('data', () => {})).listen(0, '127.0.0.1', () => {
  const port = server.address().port;
  const c = connect(port, '127.0.0.1', () => {
    c.write('hello');
    const child = spawn(process.execPath, ['-e', 'setTimeout(()=>{}, 1500)'], { stdio: 'ignore' });
    setTimeout(() => {
      process.stdout.write(JSON.stringify({ pid: process.pid, marker, fd, port, clientPort: c.localPort, child: child.pid }) + '\n');
      setTimeout(() => process.exit(7), 200);
    }, Number(process.argv[2] ?? 1200));
  });
});
