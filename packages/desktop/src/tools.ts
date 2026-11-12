// Agent tools that only parse data (safe in a browser worker): plists, .desktop entries, reg query
// output, /proc text, lsof -F output, gdbus replies and snapshot comparison.
import { parsePlist } from './plist.js';
import { parseDesktopFile, desktopEntryToApp, parseRegQuery, uninstallKeysToApps, infoPlistToApp } from './apps.js';
import { parseProcMaps, parseProcNet, parseProcNetUnix, parseProcStatus, parseLsofF, InputError } from './proc.js';
import { parseGVariant } from './gvariant.js';
import { compareSnapshots } from './compare.js';
import { compareUiTrees } from './uimodel.js';
import { parseStrace, compareCaptures } from './strace.js';
import { readLevelLog, decodeLocalStorage } from './leveldb.js';
import { validateTask, toEvalTasks, scoreTaskAnswers, type DesktopTask } from './views.js';
import { decodeXwd, pngInfo } from './image.js';

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
async function jsonOf(path: unknown, text: unknown, read?: Reader, max = 256 * 1024 * 1024): Promise<any> {
  const t = typeof text === 'string' ? text : typeof path === 'string' ? new TextDecoder().decode(await bytesOf({ path }, read, max)) : undefined;
  if (t === undefined) throw new InputError('give a file path or the JSON text');
  try { return JSON.parse(t); } catch { throw new InputError('input is not JSON'); }
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
      {
      name: 'desktop_ui_compare',
      description: 'Diff two UI trees (from desktop_ui_tree, a checkpoint ui-tree.json or a scenario step) from any backend: elements added and removed, and changed names, states, values, text, bounds and actions, keyed by their role and name path. Gives a 0 to 1 similarity.',
      inputSchema: { a: { type: 'string', description: 'First tree JSON file (Node).', optional: true }, b: { type: 'string', description: 'Second tree JSON file (Node).', optional: true }, aText: { type: 'string', description: 'First tree as JSON text.', optional: true }, bText: { type: 'string', description: 'Second tree as JSON text.', optional: true }, ignore: { type: 'array', description: 'Fields to ignore, such as bounds.', optional: true }, limit: { type: 'number', description: 'Max items per list (default 2000).', optional: true } },
      run: async (i) => compareUiTrees(await jsonOf(i.a, i.aText, read), await jsonOf(i.b, i.bText, read), { limit: i.limit, ignore: i.ignore }),
    },
    {
      name: 'desktop_capture_compare',
      description: 'Compare two process captures from desktop_process_capture: modules, files, sockets and processes that appear in only one run, syscall count changes, executed programs, network endpoints, exit status, duration and peak memory.',
      inputSchema: { a: { type: 'string', description: 'First capture file (Node).', optional: true }, b: { type: 'string', description: 'Second capture file (Node).', optional: true }, aText: { type: 'string', description: 'First capture JSON text.', optional: true }, bText: { type: 'string', description: 'Second capture JSON text.', optional: true }, limit: { type: 'number', description: 'Max items per list.', optional: true } },
      run: async (i) => compareCaptures(await jsonOf(i.a, i.aText, read, 512 * 1024 * 1024), await jsonOf(i.b, i.bText, read, 512 * 1024 * 1024), { limit: i.limit }),
    },
    {
      name: 'desktop_strace_parse',
      description: 'Summarise strace output (-f -tt -T optional): calls and errors per syscall, files touched with the operations, programs executed with argv, network endpoints from connect, bind and sendto, process tree from clone and fork, and signals. Linear time, bounded.',
      inputSchema: { ...SRC, maxItems: { type: 'number', description: 'Cap for each list (default 20000).', optional: true } },
      run: async (i) => parseStrace(await textOf(i, read), { maxItems: i.maxItems }),
    },
    {
      name: 'desktop_leveldb_log',
      description: 'Read a LevelDB .log file (Chromium and Electron Local Storage, Session Storage, IndexedDB): every put and delete with its sequence number. With localStorage=true, keys and values are decoded as Chromium Local Storage (origin, key, value).',
      inputSchema: { ...SRC, localStorage: { type: 'boolean', description: 'Decode Chromium Local Storage records.', optional: true }, limit: { type: 'number', description: 'Max records (default 2000).', optional: true } },
      run: async (i) => {
        const r = readLevelLog(await bytesOf(i, read), { maxRecords: Math.max(1, Math.min(Number(i.limit ?? 2000), 100_000)) });
        const hex = (b: Uint8Array) => Array.from(b.subarray(0, 256), (x) => x.toString(16).padStart(2, '0')).join('');
        const txt = (b: Uint8Array) => new TextDecoder('utf-8', { fatal: false }).decode(b.subarray(0, 2000));
        return { batches: r.batches, corrupt: r.corrupt, truncated: r.truncated, records: r.records.map((x) => i.localStorage ? { seq: x.seq, op: x.op, ...decodeLocalStorage(x.key, x.value) } : { seq: x.seq, op: x.op, key: txt(x.key), keyHex: hex(x.key), value: x.value ? txt(x.value) : undefined, valueBytes: x.value?.length }) };
      },
    },
    {
      name: 'desktop_task_validate',
      description: 'Check a desktop task file ({name, prompt, checks}) against the task rules: check kinds (file_present, lines_present, value_equals, text_contains, member_count, row_count, ui_element and the rest), relative file paths, pointers, counts, tolerances and date-like values. Also returns the checks as eval tasks for x_eval_score.',
      inputSchema: { ...SRC },
      run: async (i) => { let t: DesktopTask; try { t = JSON.parse(await textOf(i, read)); } catch { throw new InputError('task must be JSON'); } const problems = validateTask(t); return { valid: !problems.length, problems, evalTasks: problems.length ? [] : toEvalTasks(t) }; },
    },
    {
      name: 'desktop_task_score',
      description: 'Score answers for a desktop task the way x_eval_score scores exact answers: answers maps "<task>/<check>" to pass or fail (desktop_task_check returns that map). Gives score, accuracy, by-tag totals and per-check results.',
      inputSchema: { task: { type: 'object', description: 'The task object.' }, answers: { type: 'object', description: 'Map of "<task>/<check>" to pass or fail.' }, agent: { type: 'string', description: 'Label for who solved it.', optional: true } },
      run: async (i) => { const problems = validateTask(i.task); if (problems.length) throw new InputError(`invalid task: ${problems.join('; ')}`); return scoreTaskAnswers(i.task, (i.answers ?? {}) as Record<string, unknown>, i.agent); },
    },
    {
      name: 'desktop_screenshot_info',
      description: 'Read a screenshot: PNG size and colour type, or an X Window Dump (xwd) decoded to its size, window name and the RGB value at a point.',
      inputSchema: { ...SRC, x: { type: 'number', description: 'Pixel x for an XWD colour probe.', optional: true }, y: { type: 'number', description: 'Pixel y for an XWD colour probe.', optional: true } },
      run: async (i) => {
        const b = await bytesOf(i, read, 256 * 1024 * 1024);
        if (b[0] === 0x89 && b[1] === 0x50) return { format: 'png', ...pngInfo(b) };
        const img = decodeXwd(b);
        const at = typeof i.x === 'number' && typeof i.y === 'number' && i.x >= 0 && i.y >= 0 && i.x < img.width && i.y < img.height ? Array.from(img.data.subarray((Math.floor(i.y) * img.width + Math.floor(i.x)) * 4, (Math.floor(i.y) * img.width + Math.floor(i.x)) * 4 + 3)) : undefined;
        return { format: 'xwd', width: img.width, height: img.height, name: img.name, rgbAt: at };
      },
    },
  ];
}
