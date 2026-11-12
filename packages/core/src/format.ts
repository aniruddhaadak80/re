import type { FormatId } from './types.js';
import { startsWith, looksTextual, decodeUtf8, indexOf, asciiBytes } from './bytes.js';

const MIME: Partial<Record<FormatId, string>> = {
  elf: 'application/x-elf', pe: 'application/vnd.microsoft.portable-executable', macho: 'application/x-mach-binary',
  'macho-fat': 'application/x-mach-binary', wasm: 'application/wasm', zip: 'application/zip', jar: 'application/java-archive',
  apk: 'application/vnd.android.package-archive', crx: 'application/x-chrome-extension', xpi: 'application/x-xpinstall',
  vsix: 'application/vsix', 'npm-tgz': 'application/gzip', gzip: 'application/gzip', tar: 'application/x-tar',
  asar: 'application/x-asar', js: 'text/javascript', sourcemap: 'application/json', json: 'application/json',
  pdf: 'application/pdf', dotnet: 'application/vnd.microsoft.portable-executable', ipa: 'application/octet-stream',
  pcap: 'application/vnd.tcpdump.pcap', pcapng: 'application/x-pcapng', sqlite: 'application/vnd.sqlite3', har: 'application/json',
  lua: 'application/x-lua-bytecode', beam: 'application/x-erlang-beam', 'il2cpp-metadata': 'application/octet-stream',
  dmg: 'application/x-apple-diskimage', pkg: 'application/vnd.apple.installer+xml', xar: 'application/x-xar', msix: 'application/msix', appx: 'application/appx',
  'dos-mz': 'application/x-dosexec', directory: 'inode/directory',
  pyc: 'application/x-python-code', dex: 'application/x-dex', class: 'application/java-vm', text: 'text/plain',
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
  if (e === 'appx' || e === 'appxbundle') return 'appx';
  if (e === 'msix' || e === 'msixbundle') return 'msix';
  if (indexOf(bytes, asciiBytes('AppxManifest.xml')) >= 0 && indexOf(bytes, asciiBytes('AppxBlockMap.xml')) >= 0) return 'msix';
  if (indexOf(bytes, asciiBytes('AppxMetadata/AppxBundleManifest.xml')) >= 0) return 'msix';
  // Peek at central directory names without fully parsing.
  if (e === 'ipa' || (indexOf(bytes, asciiBytes('Payload/')) >= 0 && indexOf(bytes, asciiBytes('.app/Info.plist')) >= 0)) return 'ipa';
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
    if (pe + 4 <= bytes.length && startsWith(bytes, [0x50, 0x45, 0, 0], pe)) return hasCliDirectory(dv, pe) ? 'dotnet' : 'pe';
  }
  // MZ without a PE header: a plain DOS program (or an NE, LE or LX image behind a DOS stub).
  if ((startsWith(bytes, [0x4d, 0x5a]) || startsWith(bytes, [0x5a, 0x4d])) && bytes.length >= 28 && isPlausibleMz(bytes)) return 'dos-mz';
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
  if (startsWith(bytes, [0x78, 0x61, 0x72, 0x21]) && bytes.length >= 28) return e === 'xip' || e === 'safariextz' || e === 'xar' ? 'xar' : 'pkg';
  if (hasKolyTrailer(bytes)) return 'dmg';
  for (const m of [[0xd4, 0xc3, 0xb2, 0xa1], [0xa1, 0xb2, 0xc3, 0xd4], [0x4d, 0x3c, 0xb2, 0xa1], [0xa1, 0xb2, 0x3c, 0x4d]]) {
    if (startsWith(bytes, m) && bytes.length >= 24) return 'pcap';
  }
  if (startsWith(bytes, [0x0a, 0x0d, 0x0d, 0x0a]) && bytes.length >= 28) return 'pcapng';
  if (startsWith(bytes, Array.from(asciiBytes('SQLite format 3\0')))) return 'sqlite';
  if (startsWith(bytes, [0x1b, 0x4c, 0x75, 0x61]) || startsWith(bytes, [0x1b, 0x4c, 0x4a])) return 'lua';
  if (startsWith(bytes, Array.from(asciiBytes('FOR1'))) && startsWith(bytes, Array.from(asciiBytes('BEAM')), 8)) return 'beam';
  if (startsWith(bytes, [0xaf, 0x1b, 0xb1, 0xfa]) && bytes.length >= 8) return 'il2cpp-metadata';
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
      if (e === 'har' || /^\{\s*"log"\s*:\s*\{/.test(head)) return 'har';
      if (e === 'json' || /^\{\s*"/.test(head)) return 'json';
    }
    if (['js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx'].includes(e)) return 'js';
    if (/\b(function|=>|const|var|let|import|export|require\()\b/.test(head) && /[;{}()]/.test(head)) return 'js';
    return 'text';
  }
  return 'unknown';
}

/** UDIF disk images end with a 512 byte trailer that starts with "koly", version 4, header size 512. */
function hasKolyTrailer(b: Uint8Array): boolean {
  if (b.length < 1024) return false;
  const t = b.length - 512;
  return b[t] === 0x6b && b[t + 1] === 0x6f && b[t + 2] === 0x6c && b[t + 3] === 0x79 && b[t + 8] === 0 && b[t + 9] === 0 && b[t + 10] === 2 && b[t + 11] === 0;
}

/** An MZ header whose header size and page count make sense; rules out random data that starts with MZ. */
function isPlausibleMz(b: Uint8Array): boolean {
  const u16 = (o: number): number => (b[o] as number) | ((b[o + 1] as number) << 8);
  const lastPage = u16(2), pages = u16(4), hdrPara = u16(8), relocOff = u16(24), nrel = u16(6);
  if (pages === 0 || lastPage > 511 || hdrPara === 0) return false;
  const image = pages * 512 - (lastPage ? 512 - lastPage : 0);
  if (hdrPara * 16 > image) return false;
  if (nrel && relocOff + nrel * 4 > hdrPara * 16 && relocOff + nrel * 4 > b.length) return false;
  return true;
}

export function isTextFormat(f: FormatId): boolean {
  return f === 'js' || f === 'json' || f === 'sourcemap' || f === 'text' || f === 'har';
}

/** The broader family a format belongs to: a .NET assembly is a PE, an IPA is a ZIP, pcapng is a capture. */
export function formatFamily(f: FormatId): FormatId {
  if (f === 'dotnet') return 'pe';
  if (f === 'ipa') return 'zip';
  if (f === 'pcapng') return 'pcap';
  if (f === 'har') return 'json';
  if (f === 'msix' || f === 'appx') return 'zip';
  if (f === 'pkg') return 'xar';
  return f;
}

/** True when the PE optional header has a non-empty CLI (COM descriptor) data directory, which marks a .NET assembly. */
function hasCliDirectory(dv: DataView, pe: number): boolean {
  const opt = pe + 24;
  if (opt + 2 > dv.byteLength) return false;
  const magic = dv.getUint16(opt, true);
  const dirs = magic === 0x20b ? opt + 112 : magic === 0x10b ? opt + 96 : -1;
  if (dirs < 0) return false;
  const countOff = dirs - 4;
  if (countOff + 4 > dv.byteLength || dv.getUint32(countOff, true) < 15) return false;
  const cli = dirs + 14 * 8;
  if (cli + 8 > dv.byteLength) return false;
  return dv.getUint32(cli, true) !== 0 && dv.getUint32(cli + 4, true) !== 0;
}
