import type { FormatId } from './types.js';
import { startsWith, looksTextual, decodeUtf8, indexOf, asciiBytes } from './bytes.js';

const MIME: Partial<Record<FormatId, string>> = {
  elf: 'application/x-elf', pe: 'application/vnd.microsoft.portable-executable', macho: 'application/x-mach-binary',
  'macho-fat': 'application/x-mach-binary', wasm: 'application/wasm', zip: 'application/zip', jar: 'application/java-archive',
  apk: 'application/vnd.android.package-archive', crx: 'application/x-chrome-extension', xpi: 'application/x-xpinstall',
  vsix: 'application/vsix', 'npm-tgz': 'application/gzip', gzip: 'application/gzip', tar: 'application/x-tar',
  asar: 'application/x-asar', js: 'text/javascript', sourcemap: 'application/json', json: 'application/json',
  pdf: 'application/pdf', pyc: 'application/x-python-code', dex: 'application/x-dex', class: 'application/java-vm', text: 'text/plain',
};

export function mimeOf(f: FormatId): string | undefined { return MIME[f]; }

function ext(name: string): string {
  const i = name.lastIndexOf('.');
  return i >= 0 ? name.slice(i + 1).toLowerCase() : '';
}

function zipFlavor(bytes: Uint8Array, name: string): FormatId {
  const e = ext(name);
  if (e === 'apk' || e === 'aab') return 'apk';
  if (e === 'jar' || e === 'war' || e === 'aar') return 'jar';
  if (e === 'xpi') return 'xpi';
  if (e === 'vsix') return 'vsix';
  if (e === 'crx') return 'crx';
  // Peek at central directory names without fully parsing.
  if (indexOf(bytes, asciiBytes('AndroidManifest.xml')) >= 0 && indexOf(bytes, asciiBytes('classes.dex')) >= 0) return 'apk';
  if (indexOf(bytes, asciiBytes('extension.vsixmanifest')) >= 0) return 'vsix';
  if (indexOf(bytes, asciiBytes('META-INF/MANIFEST.MF')) >= 0) return 'jar';
  return 'zip';
}

/** Identify a file by magic bytes first, then by name and content sniffing. */
export function detectFormat(bytes: Uint8Array, name = ''): FormatId {
  const e = ext(name);
  if (startsWith(bytes, [0x7f, 0x45, 0x4c, 0x46])) return 'elf';
  if (startsWith(bytes, [0x4d, 0x5a]) && bytes.length > 0x40) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const pe = dv.getUint32(0x3c, true);
    if (pe + 4 <= bytes.length && startsWith(bytes, [0x50, 0x45, 0, 0], pe)) return 'pe';
  }
  if (startsWith(bytes, [0xca, 0xfe, 0xba, 0xbe])) {
    // Mach-O fat vs Java class: fat has a small arch count, class has major version >= 45.
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const n = bytes.length >= 8 ? dv.getUint32(4, false) : 0;
    return n > 0 && n < 30 ? 'macho-fat' : 'class';
  }
  for (const m of [[0xfe, 0xed, 0xfa, 0xce], [0xce, 0xfa, 0xed, 0xfe], [0xfe, 0xed, 0xfa, 0xcf], [0xcf, 0xfa, 0xed, 0xfe]]) {
    if (startsWith(bytes, m)) return 'macho';
  }
  if (startsWith(bytes, [0x00, 0x61, 0x73, 0x6d])) return 'wasm';
  if (startsWith(bytes, [0x43, 0x72, 0x32, 0x34])) return 'crx'; // "Cr24"
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04]) || startsWith(bytes, [0x50, 0x4b, 0x05, 0x06])) return zipFlavor(bytes, name);
  if (startsWith(bytes, [0x1f, 0x8b])) return e === 'tgz' || name.endsWith('.tar.gz') && /-\d+\.\d+\.\d+/.test(name) ? 'npm-tgz' : (e === 'tgz' ? 'npm-tgz' : 'gzip');
  if (bytes.length > 262 && startsWith(bytes, [0x75, 0x73, 0x74, 0x61, 0x72], 257)) return 'tar';
  if (startsWith(bytes, [0x25, 0x50, 0x44, 0x46])) return 'pdf';
  if (startsWith(bytes, [0x64, 0x65, 0x78, 0x0a])) return 'dex';
  if (bytes.length >= 16 && bytes[2] === 0x0d && bytes[3] === 0x0a && e === 'pyc') return 'pyc';
  if (e === 'asar' || (startsWith(bytes, [0x04, 0, 0, 0]) && bytes.length > 16 && bytes[12] === 0x7b /* { */)) return 'asar';
  if (looksTextual(bytes)) {
    if (e === 'map') return 'sourcemap';
    const head = decodeUtf8(bytes.subarray(0, Math.min(bytes.length, 2048))).trimStart();
    if (head.startsWith('{')) {
      if (/"mappings"\s*:/.test(head) && /"version"\s*:\s*3/.test(head)) return 'sourcemap';
      if (e === 'json' || /^\{\s*"/.test(head)) return 'json';
    }
    if (['js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx'].includes(e)) return 'js';
    if (/\b(function|=>|const|var|let|import|export|require\()\b/.test(head) && /[;{}()]/.test(head)) return 'js';
    return 'text';
  }
  return 'unknown';
}

export function isTextFormat(f: FormatId): boolean {
  return f === 'js' || f === 'json' || f === 'sourcemap' || f === 'text';
}
