#!/usr/bin/env node
// RevLens MCP server. stdio by default; --http starts Streamable HTTP on 127.0.0.1 (see http.ts).
// Bridge sessions (radare2, gdb, lldb, Frida) are closed when the server stops, whichever way it stops.
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { closeAllSessions, killAllSessions } from '@revlens/engine/node';
import { createServer } from './server.js';
import { httpOptionsFromArgv, startHttpServer } from './http.js';

let stopping = false;
/** Close sessions politely with a time limit, then exit. */
function shutdown(code: number, extra?: () => Promise<unknown>): void {
  if (stopping) return;
  stopping = true;
  const limit = setTimeout(() => { killAllSessions(); process.exit(code); }, 5_000);
  limit.unref();
  void Promise.resolve(extra?.()).catch(() => undefined)
    .then(() => closeAllSessions().catch(() => 0))
    .finally(() => { clearTimeout(limit); process.exit(code); });
}
process.once('exit', () => killAllSessions());

const http = httpOptionsFromArgv(process.argv.slice(2));
if (http) {
  const h = await startHttpServer(http);
  process.stderr.write(`RevLens MCP listening on ${h.url}${http.token ? ' (bearer token required)' : ''}\n`);
  process.on('SIGINT', () => shutdown(0, () => h.close()));
  process.on('SIGTERM', () => shutdown(0, () => h.close()));
} else {
  const { server } = createServer();
  const transport = new StdioServerTransport();
  // the client closing stdin is the usual way a stdio MCP server is told to stop
  process.stdin.once('end', () => shutdown(0, () => server.close()));
  process.stdin.once('close', () => shutdown(0, () => server.close()));
  process.on('SIGINT', () => shutdown(0, () => server.close()));
  process.on('SIGTERM', () => shutdown(0, () => server.close()));
  await server.connect(transport);
}
