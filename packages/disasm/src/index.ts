// @revlens/disasm public entry (browser and worker safe; path inputs need Node or setFileReader).
export * from './types.js';
export { loadImage, detectBinFormat, type LoadOptions } from './loader/index.js';
export { Memory } from './loader/memory.js';
export { loadDecoders, type DecoderOptions, type DecoderSet } from './backends/index.js';
export { Program, normName, type OpenOptions } from './analysis/program.js';
export { liftFunction, type LiftResult } from './analysis/lift.js';
export { stringAt } from './analysis/strings.js';
export {
  openProgram, clearSessions, setFileReader, resolveFunction, summarizeFunction,
  disasmInfo, disasmListFunctions, disasmFunction, disasmPseudocode, disasmXrefs, disasmCallgraph,
  disasmSearch, disasmFindReferences, disasmCallPaths, disasmAt, type BinaryInput,
} from './api.js';
export { TOOLS, type Tool, type ToolParam } from './tools.js';
export { CLI_COMMANDS, type CliCommand } from './cli.js';
export { disasmAnalyzer } from './analyzer.js';
import { disasmAnalyzer } from './analyzer.js';
export const ANALYZERS = [disasmAnalyzer];
