// Windows Shell Link (.lnk) files per MS-SHLLINK: header, target ID list, link info,
// string data and extra data blocks (tracker machine id, environment, known folder).

import { View, ParseError, guid, filetime, hexs } from '../util.js';

const FLAG_NAMES = ['HasLinkTargetIDList', 'HasLinkInfo', 'HasName', 'HasRelativePath', 'HasWorkingDir', 'HasArguments', 'HasIconLocation', 'IsUnicode', 'ForceNoLinkInfo', 'HasExpString', 'RunInSeparateProcess', 'Unused1', 'HasDarwinID', 'RunAsUser', 'HasExpIcon', 'NoPidlAlias', 'Unused2', 'RunWithShimLayer', 'ForceNoLinkTrack', 'EnableTargetMetadata', 'DisableLinkPathTracking', 'DisableKnownFolderTracking', 'DisableKnownFolderAlias', 'AllowLinkToLink', 'UnaliasOnSave', 'PreferEnvironmentPath', 'KeepLocalIDListForUNCTarget'];
const ATTR_NAMES: [number, string][] = [[0x1, 'READONLY'], [0x2, 'HIDDEN'], [0x4, 'SYSTEM'], [0x10, 'DIRECTORY'], [0x20, 'ARCHIVE'], [0x80, 'NORMAL'], [0x100, 'TEMPORARY'], [0x800, 'COMPRESSED'], [0x4000, 'ENCRYPTED']];
const SHOW: Record<number, string> = { 1: 'SW_SHOWNORMAL', 3: 'SW_SHOWMAXIMIZED', 7: 'SW_SHOWMINNOACTIVE' };
const DRIVE: Record<number, string> = { 0: 'DRIVE_UNKNOWN', 1: 'DRIVE_NO_ROOT_DIR', 2: 'DRIVE_REMOVABLE', 3: 'DRIVE_FIXED', 4: 'DRIVE_REMOTE', 5: 'DRIVE_CDROM', 6: 'DRIVE_RAMDISK' };
const BLOCKS: Record<number, string> = { 0xa0000001: 'EnvironmentVariableDataBlock', 0xa0000002: 'ConsoleDataBlock', 0xa0000003: 'TrackerDataBlock', 0xa0000004: 'ConsoleFEDataBlock', 0xa0000005: 'SpecialFolderDataBlock', 0xa0000006: 'DarwinDataBlock', 0xa0000007: 'IconEnvironmentDataBlock', 0xa0000008: 'ShimDataBlock', 0xa0000009: 'PropertyStoreDataBlock', 0xa000000b: 'KnownFolderDataBlock', 0xa000000c: 'VistaAndAboveIDListDataBlock' };
const KNOWN_CLSID: Record<string, string> = { '20D04FE0-3AEA-1069-A2D8-08002B30309D': 'My Computer', '450D8FBA-AD25-11D0-98A8-0800361B1103': 'My Documents', '59031A47-3F72-44A7-89C5-5595FE6B30EE': 'User Profile', 'F02C1A0D-BE21-4350-88B0-7367FC96EF3C': 'Network' };

export interface LnkIdItem { offset: number; size: number; type: string; value?: string }
export interface Lnk {
  flags: string[];
  attributes: string[];
  created: string | null;
  accessed: string | null;
  modified: string | null;
  fileSize: number;
  iconIndex: number;
  showCommand: string;
  hotKey: string;
  idList: LnkIdItem[];
  idListPath?: string;
  linkInfo?: { flags: number; driveType?: string; driveSerial?: string; volumeLabel?: string; localBasePath?: string; networkShare?: string; commonPathSuffix?: string; offset: number };
  name?: string;
  relativePath?: string;
  workingDir?: string;
  arguments?: string;
  iconLocation?: string;
  target?: string;
  extra: { offset: number; size: number; signature: string; block: string; machineId?: string; droidVolume?: string; droidFile?: string; environment?: string; knownFolder?: string }[];
}

function idItem(v: View, o: number, size: number): LnkIdItem {
  const t = size > 2 ? v.u8(o + 2) : 0;
  if (t === 0x1f && size >= 20) { const g = guid(v.bytes, o + 4); return { offset: o, size, type: 'root', value: KNOWN_CLSID[g] ?? `{${g}}` }; }
  if ((t & 0x70) === 0x20 && size >= 6) return { offset: o, size, type: 'volume', value: v.cstr(o + 3, Math.min(size - 3, 64)) };
  if ((t & 0x70) === 0x30 && size >= 15) {
    const short = v.cstr(o + 14, Math.min(size - 14, 260));
    // a BEEF0004 extension block after the short name carries the long Unicode name
    let long: string | undefined;
    let p = o + 14 + short.length + 1;
    if (p % 2) p++;
    if (v.has(p + 8, 4) && v.u32(p + 4) === 0xbeef0004) {
      const extSize = v.u16(p), ver = v.u16(p + 2);
      const nameOff = p + (ver >= 9 ? 46 : ver >= 7 ? 42 : ver >= 3 ? 22 : 18);
      if (nameOff < p + extSize) long = v.utf16z(nameOff, 260);
    }
    return { offset: o, size, type: (t & 0x01) ? 'directory' : 'file', value: long || short };
  }
  return { offset: o, size, type: `type-${hexs(t, 2)}` };
}

/** Parse a .lnk shell link. */
export function parseLnk(b: Uint8Array, maxItems = 256): Lnk {
  const v = new View(b, true);
  if (b.length < 0x4c || v.u32(0) !== 0x4c || guid(b, 4) !== '00021401-0000-0000-C000-000000000046') throw new ParseError('not a shell link (header size 0x4C and CLSID 00021401 expected)', 0);
  const fl = v.u32(0x14);
  const attrs = v.u32(0x18);
  const hk = v.u16(0x40);
  const out: Lnk = {
    flags: FLAG_NAMES.filter((_, i) => fl & (1 << i)), attributes: ATTR_NAMES.filter(([m]) => attrs & m).map(([, n]) => n),
    created: filetime(v.u32(0x1c), v.u32(0x20)), accessed: filetime(v.u32(0x24), v.u32(0x28)), modified: filetime(v.u32(0x2c), v.u32(0x30)),
    fileSize: v.u32(0x34), iconIndex: v.i32(0x38), showCommand: SHOW[v.u32(0x3c)] ?? String(v.u32(0x3c)), hotKey: hk ? hexs(hk, 4) : 'none', idList: [], extra: [],
  };
  let p = 0x4c;
  if (fl & 0x1) {
    const total = v.u16(p);
    const end = p + 2 + total;
    let q = p + 2;
    while (q + 2 <= end && out.idList.length < maxItems) {
      const s = v.u16(q);
      if (s === 0) break;
      if (s < 2 || q + s > end) break;
      out.idList.push(idItem(v, q, s));
      q += s;
    }
    const parts = out.idList.filter((x) => x.type === 'volume' || x.type === 'file' || x.type === 'directory').map((x) => x.value ?? '');
    if (parts.length) out.idListPath = parts.map((x, i) => (i === 0 || x.endsWith('\\') ? x : x)).reduce((a, x) => (a === '' ? x : a.endsWith('\\') ? a + x : a + '\\' + x), '');
    p = end;
  }
  if ((fl & 0x2) && !(fl & 0x100)) {
    const size = v.u32(p), hs = v.u32(p + 4), lf = v.u32(p + 8);
    const li: NonNullable<Lnk['linkInfo']> = { flags: lf, offset: p };
    const volOff = v.u32(p + 12), baseOff = v.u32(p + 16), cnrlOff = v.u32(p + 20), sufOff = v.u32(p + 24);
    if ((lf & 1) && volOff) {
      const vb = p + volOff;
      li.driveType = DRIVE[v.u32(vb + 4)] ?? String(v.u32(vb + 4));
      li.driveSerial = hexs(v.u32(vb + 8), 8);
      const lo = v.u32(vb + 12);
      li.volumeLabel = lo === 0x14 ? v.utf16z(vb + v.u32(vb + 16), 64) : v.cstr(vb + lo, 64);
    }
    if ((lf & 1) && baseOff) li.localBasePath = hs >= 0x24 && v.u32(p + 28) ? v.utf16z(p + v.u32(p + 28), 1024) : v.cstr(p + baseOff, 1024);
    if ((lf & 2) && cnrlOff) { const cb = p + cnrlOff; const no = v.u32(cb + 8); if (no) li.networkShare = v.cstr(cb + no, 1024); }
    if (sufOff) li.commonPathSuffix = hs >= 0x24 && v.has(p + 32, 4) && v.u32(p + 32) ? v.utf16z(p + v.u32(p + 32), 1024) : v.cstr(p + sufOff, 1024);
    out.linkInfo = li;
    p += size;
  }
  const uni = (fl & 0x80) !== 0;
  const sd = (): string => { const n = v.u16(p); p += 2; const s = uni ? v.utf16(p, n) : String.fromCharCode(...v.sub(p, n)); p += uni ? n * 2 : n; return s; };
  if (fl & 0x4) out.name = sd();
  if (fl & 0x8) out.relativePath = sd();
  if (fl & 0x10) out.workingDir = sd();
  if (fl & 0x20) out.arguments = sd();
  if (fl & 0x40) out.iconLocation = sd();
  for (let k = 0; k < 64 && v.has(p, 4); k++) {
    const size = v.u32(p);
    if (size < 4) break;
    if (size < 8 || !v.has(p, size)) break;
    const sig = v.u32(p + 4);
    const blk: Lnk['extra'][number] = { offset: p, size, signature: hexs(sig, 8), block: BLOCKS[sig] ?? 'unknown' };
    if (sig === 0xa0000003 && size >= 0x60) {
      blk.machineId = v.cstr(p + 16, 16);
      blk.droidVolume = guid(b, p + 32); blk.droidFile = guid(b, p + 48);
    } else if ((sig === 0xa0000001 || sig === 0xa0000007) && size >= 0x314) {
      blk.environment = v.utf16z(p + 8 + 260, 260) || v.cstr(p + 8, 260);
    } else if (sig === 0xa000000b && size >= 0x1c) blk.knownFolder = guid(b, p + 8);
    out.extra.push(blk);
    p += size;
  }
  const li = out.linkInfo;
  const lb = li?.localBasePath ?? (li?.networkShare ? li.networkShare : undefined);
  if (lb !== undefined) out.target = li?.commonPathSuffix ? (lb.endsWith('\\') ? lb + li.commonPathSuffix : `${lb}\\${li.commonPathSuffix}`) : lb;
  else if (out.idListPath) out.target = out.idListPath;
  return out;
}
