// @revlens/webrt: reverse engineering for JavaScript apps, Electron, browsers, network captures and data files.
// This entry is safe to load in a browser Web Worker. Node-only features live in '@revlens/webrt/node'.
export { parseJs, walk } from './js/ast.js';
export { beautify, type BeautifyResult } from './js/print.js';
export { deobfuscate, type DeobfuscateResult } from './js/deobfuscate.js';
export { unpackBundle, type BundleResult, type BundleModule, type BundlerKind } from './js/bundle.js';
export { findEndpoints, type EndpointReport, type EndpointCall } from './js/endpoints.js';
export { recoverSources, decodeMappings, inlineSourceMap, sourceMapUrl, parseSourceMap, SourceMapIndex, type RawSourceMap, type SourceMapRecovery } from './sourcemap.js';
export { readAsar, readAsarFile, isAsar, resolveAsarLink, type AsarArchive, type AsarEntry } from './asar.js';
export { auditElectron, auditAsar, readFuses, detectElectronVersionInBinary, FUSE_NAMES, FUSE_SENTINEL, type ElectronAudit, type ElectronSources } from './electron.js';
export { analyzePcap, readPackets, decodeFrame, parseDns, parseClientHello, parseServerHello, isPcap, linkTypeName, type PcapAnalysis, type Flow, type TlsHello, type DnsMessage, type HttpMessage } from './pcap.js';
export { SqliteFile, runSelect, parseSelect, parseCreateTable, sampleRows, isSqlite, jsonValue, type QueryResult, type TableInfo, type SqlValue } from './sqlite.js';
export { analyzeHar, looksLikeHar, type HarSummary } from './har.js';
export { md5Hex, safeRelPath, InputError, LIMITS } from './util.js';
export { makeTools, loadBytes, type ToolDef, type ToolIO } from './tools.js';
export { ANALYZERS, webJsAnalyzer, webSourcemapAnalyzer, webElectronAnalyzer, webPcapAnalyzer, webSqliteAnalyzer, webHarAnalyzer, obfuscationScore } from './analyzers.js';

import { makeTools } from './tools.js';
/** Agent tools that take bytes (base64) or text. Use the TOOLS from '@revlens/webrt/node' for file paths and browser capture. */
export const TOOLS = makeTools();
