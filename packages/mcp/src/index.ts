#!/usr/bin/env node
// RevLens MCP server. stdio by default; --http starts Streamable HTTP on 127.0.0.1 (see http.ts).
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server.js';
import { httpOptionsFromArgv, startHttpServer } from './http.js';

const http = httpOptionsFromArgv(process.argv.slice(2));
if (http) {
  const h = await startHttpServer(http);
  process.stderr.write(`RevLens MCP listening on ${h.url}${http.token ? ' (bearer token required)' : ''}\n`);
  const stop = () => { void h.close().then(() => process.exit(0)); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
} else {
  const { server } = createServer();
  await server.connect(new StdioServerTransport());
}
