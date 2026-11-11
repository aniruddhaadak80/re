#!/usr/bin/env node
// RevLens MCP server on stdio. See server.ts for the tools, resources and prompts.
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server.js';

const { server } = createServer();
await server.connect(new StdioServerTransport());
