// Analyzer registry. Order matters: structure first, then content, then rules and summaries.
import type { Analyzer } from '../types.js';
import { elfAnalyzer } from './elf.js';
import { peAnalyzer } from './pe.js';
import { machoAnalyzer } from './macho.js';
import { wasmAnalyzer } from './wasm.js';
import { buildinfoAnalyzer } from './buildinfo.js';
import { entropyAnalyzer } from './entropy.js';
import { stringsAnalyzer } from './strings.js';
import { archiveAnalyzer } from './archive.js';
import { extAuditAnalyzer } from './extaudit.js';
import { bundleSbomAnalyzer } from './sbom.js';
import { sourcemapAnalyzer } from './sourcemap.js';
import { secretsAnalyzer } from './secrets.js';
import { surfaceAnalyzer } from './surface.js';
import { capaAnalyzer } from './capa.js';
import { yaraAnalyzer } from './yara.js';
import { installersAnalyzer } from './installers.js';

export const ANALYZER_LIST: Analyzer[] = [
  elfAnalyzer, peAnalyzer, machoAnalyzer, wasmAnalyzer, installersAnalyzer, buildinfoAnalyzer,
  entropyAnalyzer, stringsAnalyzer,
  archiveAnalyzer, extAuditAnalyzer,
  bundleSbomAnalyzer, sourcemapAnalyzer, secretsAnalyzer, surfaceAnalyzer,
  capaAnalyzer, yaraAnalyzer,
];

export const ANALYZERS = ANALYZER_LIST.map(({ id, title, description }) => ({ id, title, description }));
