// Bridge sessions end with the MCP server: open a radare2 session over stdio, close the client, and check
// that the r2 process is gone. Skipped when radare2 is not installed (the bridges integration workflow has it).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { detect } from '@revlens/bridges/node';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const ELF = join(root, 'samples', 'bridges', 'crackme-aarch64.elf');
const r2 = await detect('radare2');

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch { return false; }
}
async function gone(pid: number, ms = 10_000): Promise<boolean> {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (!alive(pid)) return true; await new Promise((r) => setTimeout(r, 100)); }
  return !alive(pid);
}

test('MCP stdio server closes radare2 sessions when the client goes away', { skip: !r2.available && 'radare2 not installed' }, async () => {
  const client = new Client({ name: 'revlens-sessions-test', version: '1.0.0' });
  const transport = new StdioClientTransport({ command: process.execPath, args: ['--import', 'tsx', join(root, 'packages/mcp/src/index.ts')], cwd: root, stderr: 'inherit', env: { ...process.env } as Record<string, string> });
  await client.connect(transport);
  let pid = 0;
  try {
    const r = await client.callTool({ name: 'bridge_r2_session_open', arguments: { path: ELF, analysis: 'aa' } }) as { isError?: boolean; content: { text: string }[] };
    assert.ok(!r.isError, r.content[0]?.text);
    const o = JSON.parse(r.content[0].text);
    assert.equal(o.ok, true, r.content[0].text);
    pid = o.session.pid;
    assert.ok(pid > 0 && alive(pid));
    const l = await client.callTool({ name: 'bridge_session_list', arguments: {} }) as { content: { text: string }[] };
    assert.ok(JSON.parse(l.content[0].text).sessions.some((s: any) => s.pid === pid));
  } finally {
    await client.close();
  }
  assert.ok(await gone(pid), `r2 pid ${pid} still running after the MCP client closed`);
});
