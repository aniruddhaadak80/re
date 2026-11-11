// Long-running Node process with known open files and sockets, used by the desktop process tests.
// Prints one JSON line with what it opened. On "more" from stdin it opens one more file and a TCP
// client connection to its own server, then prints "more-done".
import { openSync, writeFileSync, mkdtempSync } from 'node:fs';
import { createServer, connect } from 'node:net';
import { createSocket } from 'node:dgram';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const dir = mkdtempSync(join(tmpdir(), 'rl-proc-'));
const fileA = join(dir, 'held-a.txt'); writeFileSync(fileA, 'a');
const fdA = openSync(fileA, 'r');
const tcp = createServer(() => {}).listen(0, '127.0.0.1');
const udp = createSocket('udp4'); udp.bind(0, '127.0.0.1');
// Windows has no Unix socket files for net.Server; a named pipe plays the same role there
const unixPath = process.platform === 'win32' ? `\\\\.\\pipe\\rl-proc-${process.pid}` : join(dir, 'rl.sock');
const unix = createServer(() => {}).listen(unixPath);
let ready = 0;
const done = () => { if (++ready === 3) process.stdout.write(JSON.stringify({ pid: process.pid, fileA, fdA, tcpPort: tcp.address().port, udpPort: udp.address().port, unixPath, dir }) + '\n'); };
tcp.on('listening', done); udp.on('listening', done); unix.on('listening', done);
const keep = [];
process.stdin.on('data', (d) => {
  if (String(d).includes('more')) {
    const fileB = join(dir, 'held-b.txt'); writeFileSync(fileB, 'b'); keep.push(openSync(fileB, 'r'));
    const c = connect(tcp.address().port, '127.0.0.1', () => process.stdout.write(JSON.stringify({ more: true, fileB, clientPort: c.localPort }) + '\n'));
    keep.push(c);
  }
});
setTimeout(() => process.exit(0), Number(process.argv[2] ?? 60000));
