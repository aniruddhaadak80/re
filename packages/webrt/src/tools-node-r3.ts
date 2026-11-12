// Node-only agent tools added in round 3: semantic runtime tracing (Node inspector and Chromium CDP).
// Further Node-only round 3 tools (Electron, existing CDP pages) are appended here as they land.
import type { ToolDef } from './tools.js';
import { traceNodeSemantics, traceBrowserSemantics, type FunctionSelector, type PageAction } from './semantics.js';
import { InputError } from './util.js';

const fnList = (v: unknown): (string | FunctionSelector)[] => {
  if (typeof v === 'string') return v.split(',').map((x) => x.trim()).filter(Boolean);
  if (!Array.isArray(v)) throw new InputError('functions must be a list of names or { name?, url?, line?, column? }');
  return v.slice(0, 200).map((f) => {
    if (typeof f === 'string') return f;
    if (f && typeof f === 'object') {
      const o = f as Record<string, unknown>;
      return { name: o.name === undefined ? undefined : String(o.name), url: o.url === undefined ? undefined : String(o.url), line: o.line === undefined ? undefined : Number(o.line), column: o.column === undefined ? undefined : Number(o.column) };
    }
    throw new InputError('bad function selector');
  });
};

export function nodeR3Tools(): ToolDef[] {
  return [
    {
      name: 'web_trace_semantics',
      description: 'Semantic runtime tracing of chosen JavaScript functions through the debugger only (rea trace_javascript_semantics, done live): run a Node script under the inspector, attach to a Node inspector port, or open a page in Chromium, and record every call of the chosen functions with argument values, every return with its value, call depth, stacks with async parents, timers (setTimeout, setInterval, animation frames) and fetch, XHR and http requests with initiator stacks. Functions are picked by name (also Class.method and esbuild renamed name2), URL part, or a line and column. Scripts are caught before they run. Logpoint mode never pauses the program. Nothing is evaluated in the target except argument reads. Node targets need allowExecution.',
      inputSchema: {
        functions: { type: 'array', description: 'Names or { name?, url?, line?, column? } selectors (line is 1-based).' },
        target: { type: 'string', description: 'node (default when script, port or wsUrl is given) or chromium (when url is given).', optional: true },
        script: { type: 'string', description: 'Node script to run under the inspector (needs allowExecution).', optional: true },
        args: { type: 'array', description: 'Arguments for the script.', optional: true },
        cwd: { type: 'string', description: 'Working folder for the script.', optional: true },
        port: { type: 'number', description: 'Attach to a Node inspector on this loopback port.', optional: true },
        wsUrl: { type: 'string', description: 'Attach to this ws:// inspector URL (loopback).', optional: true },
        url: { type: 'string', description: 'Page to open in Chromium.', optional: true },
        actions: { type: 'array', description: 'Chromium page actions after load: [{ action: click|fill|press|wait|goto, selector?, text?, key?, ms?, url? }].', optional: true },
        executablePath: { type: 'string', description: 'Chromium executable (default: REVLENS_CHROMIUM or the Playwright download).', optional: true },
        mode: { type: 'string', description: 'pause (default, records return values) or logpoint (conditional breakpoints that log, never pause).', optional: true },
        durationMs: { type: 'number', description: 'Observation time (default 5000 for Node, 3000 for Chromium, max 120000).', optional: true },
        maxEvents: { type: 'number', description: 'Event cap (default 2000).', optional: true },
        maxHitsPerFunction: { type: 'number', description: 'Stop tracing a function after this many calls (default 200).', optional: true },
        timers: { type: 'boolean', description: 'Record timers (default true).', optional: true },
        network: { type: 'boolean', description: 'Record requests with initiators (default true).', optional: true },
        stackDepth: { type: 'number', description: 'Frames kept per event (default 8).', optional: true },
        allowExecution: { type: 'boolean', description: 'Must be true for Node targets (runs or attaches to a program).', optional: true },
      },
      run: async (i) => {
        const functions = fnList(i.functions);
        const mode = i.mode === 'logpoint' ? 'logpoint' as const : 'pause' as const;
        const common = { functions, mode, durationMs: i.durationMs, maxEvents: i.maxEvents, maxHitsPerFunction: i.maxHitsPerFunction, timers: i.timers, network: i.network, stackDepth: i.stackDepth };
        const target = String(i.target ?? (i.url ? 'chromium' : 'node'));
        if (target === 'chromium') {
          if (typeof i.url !== 'string') throw new InputError('chromium tracing needs url');
          const actions: PageAction[] = Array.isArray(i.actions) ? i.actions.slice(0, 50) : [];
          return traceBrowserSemantics(i.url, { ...common, actions, executablePath: i.executablePath ?? process.env.REVLENS_CHROMIUM ?? undefined, timeoutMs: i.timeoutMs });
        }
        if (target !== 'node') throw new InputError('target is node or chromium');
        if (!i.script && !i.port && !i.wsUrl) throw new InputError('give script, port or wsUrl for a Node target');
        return traceNodeSemantics({ ...common, allowExecution: i.allowExecution, script: i.script, args: Array.isArray(i.args) ? i.args.map(String) : undefined, cwd: i.cwd, port: i.port, wsUrl: i.wsUrl });
      },
    },
  ];
}
