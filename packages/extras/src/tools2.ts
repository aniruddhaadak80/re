// Agent tools for the formats added to close the rea gap list: Windows offline artifacts,
// Apple archives, app containers, API contracts and Swift demangling.

import { inputBytes, page, ParseError, PATH_INPUT, type ToolDef, type InputSpec } from './util.js';
import { Regf } from './windows/regf.js';
import { inspectRegf } from './windows/regf.js';
import { parsePrefetch } from './windows/prefetch.js';
import { parseJumpList } from './windows/jumplist.js';
import { Cfb } from './windows/cfb.js';

const P = PATH_INPUT;
const LIMIT: Record<string, InputSpec> = {
  offset: { type: 'number', description: 'Index of the first item to return (paging)', optional: true },
  limit: { type: 'number', description: 'Maximum items to return, default 200', optional: true },
};
export const num = (x: unknown, d: number): number => (typeof x === 'number' && Number.isFinite(x) ? x : typeof x === 'string' && x.trim() !== '' && Number.isFinite(Number(x)) ? Number(x) : d);
const nameOf = (i: { path?: string; name?: string }): string | undefined => i.name ?? i.path;

export const WINDOWS_TOOLS: ToolDef[] = [
  {
    name: 'x_registry_hive',
    description: 'Windows registry hive (regf: SYSTEM, SOFTWARE, SAM, NTUSER.DAT, UsrClass.dat, Amcache.hve, BCD). Without key: header (dirty flag, checksum), root and totals. With key: that key, its subkeys and decoded values. With recursive: a paged list of every key path under it.',
    inputSchema: { ...P, key: { type: 'string', description: 'Key path below the root, backslash separated, for example Software\\Microsoft\\Windows\\CurrentVersion\\Run', optional: true }, recursive: { type: 'boolean', description: 'List all key paths under key (paged)', optional: true }, values: { type: 'boolean', description: 'With recursive, include each key\'s values', optional: true }, ...LIMIT },
    async run(i) {
      const b = await inputBytes(i);
      const r = new Regf(b);
      if (i.key === undefined && !i.recursive) return inspectRegf(b);
      const k = i.key ? r.find(String(i.key)) : r.root();
      if (!k) throw new ParseError(`key not found: ${i.key}`);
      if (i.recursive) {
        const w = r.walk(k, { maxKeys: 200000 });
        const rows = w.keys.map((x) => ({ path: x.path, lastWritten: x.lastWritten, subkeys: x.subkeyCount, values: x.valueCount, offset: x.offset }));
        const pg = page(rows, num(i.offset, 0), num(i.limit, 200));
        if (i.values) for (const row of pg.items as (typeof rows[number] & { valueList?: unknown })[]) row.valueList = r.values(r.key(row.offset), { limit: 200 });
        return { header: r.header, from: k.path, truncated: w.truncated, keys: pg };
      }
      return { header: r.header, key: k, subkeys: page(r.subkeys(k).map((s) => ({ name: s.name, lastWritten: s.lastWritten, subkeys: s.subkeyCount, values: s.valueCount, offset: s.offset })), num(i.offset, 0), num(i.limit, 200)), values: r.values(k, { limit: 2000 }) };
    },
  },
  {
    name: 'x_prefetch',
    description: 'Windows Prefetch (.pf) file, XP to 11, including Windows 10+ MAM (LZXPRESS Huffman) compressed files: executable, hash, run count, last 8 run times, loaded files, volumes with serials and directories.',
    inputSchema: { ...P, ...LIMIT },
    async run(i) {
      const p = parsePrefetch(await inputBytes(i));
      return { ...p, files: page(p.files, num(i.offset, 0), num(i.limit, 500)) };
    },
  },
  {
    name: 'x_jump_list',
    description: 'Windows Jump Lists: *.automaticDestinations-ms (DestList entries with path, pin state, access count, host, droid ids, and each embedded shell link) and *.customDestinations-ms (shell links by offset).',
    inputSchema: { ...P, name: { type: 'string', description: 'Original file name, used to report the AppID when bytes are passed', optional: true }, ...LIMIT },
    async run(i) {
      const j = parseJumpList(await inputBytes(i), { name: nameOf(i) });
      if (j.kind === 'automatic') return { ...j, entries: page(j.entries, num(i.offset, 0), num(i.limit, 200)) };
      return { ...j, links: page(j.links, num(i.offset, 0), num(i.limit, 200)) };
    },
  },
  {
    name: 'x_ole_compound',
    description: 'OLE compound file (MSI, legacy Office, Jump Lists, thumbs.db): directory entries with paths, sizes, CLSIDs and times; optionally the hex of one stream.',
    inputSchema: { ...P, stream: { type: 'string', description: 'Stream path to dump (first 4 KiB as hex)', optional: true }, ...LIMIT },
    async run(i) {
      const c = new Cfb(await inputBytes(i));
      if (i.stream) {
        const e = c.stream(String(i.stream));
        if (!e) throw new ParseError(`stream not found: ${i.stream}`);
        const d = c.read(e);
        let hex = '';
        for (const x of d.subarray(0, 4096)) hex += x.toString(16).padStart(2, '0');
        return { stream: e, hex, truncated: d.length > 4096 };
      }
      return { version: c.version, sectorSize: c.sectorSize, entries: page(c.entries.filter((e) => e.type !== 'unknown'), num(i.offset, 0), num(i.limit, 200)) };
    },
  },
];

export const GAP_TOOLS: ToolDef[] = [...WINDOWS_TOOLS];
