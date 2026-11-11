// @revlens/bridges main entry: the browser safe parts (tool catalog, output parsers, Frida hook
// templates, Ghidra and IDA scripts, MCP config merging helpers). Everything that spawns a
// process lives in '@revlens/bridges/node'.
export * from './types.js';
export { TOOL_META, TOOL_IDS, installFor, currentPlatform, type ToolMeta } from './catalog.js';
export * from './parsers/common.js';
export * from './parsers/r2.js';
export * from './parsers/objdump.js';
export * from './parsers/binwalk.js';
export * from './parsers/debugger.js';
export * from './parsers/frida.js';
export * from './parsers/adb.js';
export * from './parsers/ghidra.js';
export { HOOK_TEMPLATES, buildHookScript, HookParamError, type HookTemplate, type HookTemplateId } from './hooks.js';
export { GHIDRA_EXPORT_SCRIPT, GHIDRA_SCRIPT_NAME, IDA_EXPORT_SCRIPT } from './scripts.js';
export * from './parsers/mi.js';
export { checkR2Command, checkGdbCommand, checkLldbCommand, miQuote } from './sessions/guards.js';
export * from './names.js';
export { GHIDRA_APPLY_SCRIPT, GHIDRA_APPLY_SCRIPT_NAME, GHIDRA_NAMES_EXPORT_SCRIPT, GHIDRA_NAMES_EXPORT_SCRIPT_NAME, IDA_APPLY_SCRIPT, IDA_NAMES_EXPORT_SCRIPT } from './writeback/scripts.js';
