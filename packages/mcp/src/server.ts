// RevLens MCP server factory. The implementation lives in app.ts, which lists tools from a generated
// manifest and loads the analysis packages on first use. This module keeps the original public API,
// including TOOL_GROUPS, which needs the packages loaded; hosts that want a fast start import app.js.
export * from './app.js';
export * from './settings.js';
export { TOOL_PROFILES, MINIMAL_TOOLS, STANDARD_EXTRA, profileFromArgv, parseProfile, type ToolProfile } from './catalog.js';
export { WORKFLOWS, renderWorkflow } from './guidance/workflows.js';
export { guidance, searchGuidance, readGuidanceSection, serverInstructions } from './guidance/index.js';
export { TOOL_GROUPS } from '@revlens/engine/node';
