// Agent tools that only parse data (safe in a browser worker): plists, .desktop entries, reg query
// output, /proc text, lsof -F output, gdbus replies and snapshot comparison.
import { parsePlist } from './plist.js';
import { parseDesktopFile, desktopEntryToApp, parseRegQuery, uninstallKeysToApps, infoPlistToApp } from './apps.js';
import { parseProcMaps, parseProcNet, parseProcNetUnix, parseProcStatus, parseLsofF, InputError } from './proc.js';
import { parseGVariant } from './gvariant.js';
import { compareSnapshots } from './compare.js';

export type SchemaType = 'string' | 'number' | 'boolean' | 'array' | 'object';
export interface ToolDef { name: string; description: string; inputSchema: Record<string, { type: SchemaType; description: string; optional?: boolean }>; run: (input: any) => Promise<unknown> }

type Reader = (path: string, max: number) => Promise<Uint8Array>;

const SRC = {
  path: { type: 'string' as const, description: 'File path (Node only).', optional: true },
  base64: { type: 'string' as const, description: 'File bytes as base64.', optional: true },
  text: { type: 'string' as const, description: 'File content as text.', optional: true },
};

function b64(s: string): Uint8Array { const bin = atob(s); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }

async function bytesOf(i: { path?: string; base64?: string; text?: string }, read?: Reader, max = 64 * 1024 * 1024): Promise<Uint8Array> {
  if (typeof i.base64 === 'string') { const b = b64(i.base64); if (b.length > max) throw new InputError('input too large'); return b; }
  if (typeof i.text === 'string') { if (i.text.length > max) throw new InputError('input too large'); return new TextEncoder().encode(i.text); }
  if (typeof i.path === 'string') { if (!read) throw new InputError('file paths are only supported in Node; pass base64 or text'); return read(i.path, max); }
  throw new InputError('give one of path, base64 or text');
}
const textOf = async (i: { path?: string; base64?: string; text?: string }, read?: Reader) => (typeof i.text === 'string' ? i.text : new TextDecoder().decode(await bytesOf(i, read)));

/** Parse-only tools. Pass a file reader to accept paths (Node). */
export function BROWSER_TOOLS(read?: Reader): ToolDef[] {
  return [
    {
      name: 'desktop_plist_parse',
      description: 'Parse an XML or binary (bplist00) property list. Data values come back as base64, dates as ISO strings, UIDs as {$uid}. With bundle=true, also summarise it as an app Info.plist (id, version, executable, URL schemes).',
      inputSchema: { ...SRC, bundle: { type: 'boolean', description: 'Treat as an app Info.plist.', optional: true } },
      run: async (i) => { const v = parsePlist(await bytesOf(i, read)); return i.bundle ? { value: v, app: infoPlistToApp(v, String(i.path ?? 'App.app').replace(/\/Contents\/Info\.plist$/, '')) } : { value: v }; },
    },
    {
      name: 'desktop_entry_parse',
      description: 'Parse a freedesktop .desktop file: groups and keys, plus an app record with the executable split from Exec per the spec quoting rules, packaging (Flatpak, Snap, AppImage), categories and MIME types.',
      inputSchema: { ...SRC },
      run: async (i) => { const e = parseDesktopFile(await textOf(i, read)); return { ...e, app: desktopEntryToApp(e, String(i.path ?? 'entry.desktop')) }; },
    },
    {
      name: 'desktop_reg_uninstall_parse',
      description: 'Parse `reg query ...\\Uninstall /s` output into installed app records (name, version, publisher, install location, executable, MSI flag, uninstall command).',
      inputSchema: { ...SRC },
      run: async (i) => { const keys = parseRegQuery(await textOf(i, read)); return { keys: keys.length, apps: uninstallKeysToApps(keys) }; },
    },
    {
      name: 'desktop_proc_parse',
      description: 'Parse Linux /proc text that was copied off a machine: kind=maps (modules with base and size), status, tcp, tcp6, udp, udp6, unix (sockets with decoded addresses and states), or lsof (lsof -F output).',
      inputSchema: { ...SRC, kind: { type: 'string', description: 'maps, status, tcp, tcp6, udp, udp6, unix or lsof.' } },
      run: async (i) => {
        const t = await textOf(i, read);
        switch (i.kind) {
          case 'maps': return { modules: parseProcMaps(t) };
          case 'status': return parseProcStatus(t);
          case 'tcp': case 'tcp6': case 'udp': case 'udp6': return { sockets: parseProcNet(t, i.kind) };
          case 'unix': return { sockets: parseProcNetUnix(t) };
          case 'lsof': return { processes: parseLsofF(t) };
          default: throw new InputError('kind must be maps, status, tcp, tcp6, udp, udp6, unix or lsof');
        }
      },
    },
    {
      name: 'desktop_gvariant_parse',
      description: 'Parse GVariant text as printed by gdbus call (tuples, arrays, dicts, variants, object paths, typed numbers) into JSON.',
      inputSchema: { text: { type: 'string', description: 'gdbus output.' } },
      run: async (i) => ({ value: parseGVariant(String(i.text ?? '')) }),
    },
    {
      name: 'desktop_snapshot_compare',
      description: 'Compare two process snapshot objects (as JSON text) without touching the system: modules, files, sockets, children, memory and thread changes.',
      inputSchema: { aText: { type: 'string', description: 'First snapshot JSON.' }, bText: { type: 'string', description: 'Second snapshot JSON.' } },
      run: async (i) => { let a, b; try { a = JSON.parse(i.aText); b = JSON.parse(i.bText); } catch { throw new InputError('snapshots must be JSON'); } return compareSnapshots(a, b); },
    },
  ];
}
