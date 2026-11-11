// @revlens/bridges/node: everything, including the process runners, providers, TOOLS,
// CLI_COMMANDS and the opt in Analyzers. Node only.
export * from './index.js';
export { runTool, withTempDir, checkArgs, spawnPlan, describeFailure, EXEC_LIMITS, UnsafeArgumentError, type RunOptions } from './exec.js';
export { detect, detectAll, clearDetectionCache, findExecutable, expandPattern, parseVersion, javaMajor, readProperties, ghidraOsDir, type DetectOptions } from './detect.js';
export { inventory, formatInventory, primaryInstall } from './doctor.js';
export * from './setup.js';
export {
  BridgeInputError, requireFile, unavailable, isUnavailable, clearCache, cacheRoot, requireExecution, EXECUTION_WARNING, MAX_INPUT_BYTES,
} from './providers/common.js';
export { r2Functions, r2Disasm, r2Decompile, r2Xrefs, r2Strings, r2Info, r2Batch, checkR2Target, type R2BaseInput, type R2Engine, type R2Analysis } from './providers/radare2.js';
export { ghidraFunctions, ghidraDecompile, ghidraExport, type GhidraInput } from './providers/ghidra.js';
export { jadxDecompile, jadxSearch, apktoolDecode, ilspyDecompile, parseIlspyTypes, type JadxInput } from './providers/jvm.js';
export { fridaPs, fridaDevices, fridaRun, gdbRun, lldbRun, debugRun, gdbArgs, lldbArgs, type FridaRunInput, type DebugRunInput } from './providers/dynamic.js';
export { objdump, binwalkScan, adbDevices, adbPackages, adbPullApk, adbLogcat, idaRun, binjaFunctions, BINJA_EXPORT_SCRIPT, type ObjdumpInput } from './providers/static.js';
export {
  adbInstall, adbUninstall, adbPush, adbPull, adbStartActivity, adbStopApp, adbDumpsysPackage, adbListComponents, adbResolveActivity, adbPmPath,
  adbScreenshot, adbScreenrecord, adbDisplay, adbInput, adbGetprop, adbSettings, adbPs, adbLs, adbLogcatFiltered, adbBugreport, adbBackup, adbPortMap,
  amStartArgs, shQuote, checkRemotePath, requireDeviceChange, deviceSummary, type StartActivityInput,
} from './providers/adb.js';
export { TOOLS } from './tools.js';
export { CLI_COMMANDS, parseArgv, toolInput, renderResult } from './cli.js';
export { ANALYZERS, r2Analyzer, jadxAnalyzer, inventoryAnalyzer } from './analyzer.js';
