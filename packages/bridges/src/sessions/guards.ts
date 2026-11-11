// Command guards for interactive sessions. Pure, browser safe.
//
// A session lets an agent type tool commands. The target program is already trusted by the
// caller (allowExecution), but the debugger itself must never become a way to run host
// commands, load host scripts, write host files or switch to another program. Each guard
// returns an error message, or undefined when the command may run.

const MAX_CMD = 4096;

function basic(cmd: unknown): string | { error: string } {
  if (typeof cmd !== 'string') return { error: 'command must be a string' };
  if (cmd.length === 0 || cmd.length > MAX_CMD) return { error: `command must be 1 to ${MAX_CMD} characters` };
  if (/[\0\r\n]/.test(cmd)) return { error: 'command must be one line' };
  return cmd.trim();
}

/** True when `tok` names `word` exactly or abbreviates it (2 or more characters). */
function abbreviates(tok: string, word: string, min = 2): boolean {
  return tok === word || (tok.length >= min && word.startsWith(tok));
}

// ---------------- radare2 and rizin ----------------

/**
 * radare2 or rizin command line. cfg.sandbox is also switched on in every static session; this
 * guard is the second wall. Refused: `!` (system), backticks, `|` (pipe to a shell), `>` (write
 * output to a file), `#!` (script interpreters), and command segments that start with `.` (run a
 * script or command output), `=` (remote shell), `$` (aliases), `(` (macros), `o` open or
 * reopen, `P` projects, `w` writes, `e cfg.sandbox`, `e cmd.*` hooks, `e dir.*`, `e scr.prompt`, `e http.*`.
 */
export function checkR2Command(cmd: unknown): string | undefined {
  const b = basic(cmd);
  if (typeof b !== 'string') return b.error;
  if (/[!`|>]/.test(b)) return 'r2 sessions refuse ! ` | and > (shell, pipes and file writes)';
  if (b.includes('#!')) return 'r2 sessions refuse #! script interpreters';
  for (const raw of b.split(';')) {
    const seg = raw.trim();
    if (!seg) continue;
    const c0 = seg[0]!;
    if (c0 === '.' || c0 === '=' || c0 === '$' || c0 === '(' || c0 === '"') return `r2 sessions refuse commands starting with ${c0}`;
    if (/^o($|[\s+=.]|o|p|n|d|b)/.test(seg)) return 'r2 sessions refuse opening or reopening files (o commands)';
    if (/^P/.test(seg)) return 'r2 sessions refuse project commands; use bridge_r2_apply_names or bridge_r2_export_names';
    if (/^w/.test(seg)) return 'r2 sessions refuse write commands';
    if (/^(e|ev|ej)\s*(cfg\.sandbox|cmd\.|dir\.|scr\.prompt|http\.|key\.|file\.path|bin\.cache|io\.cache\.)/.test(seg)) return 'r2 sessions refuse changing that setting';
    if (/^(r[\s+-]|r$)/.test(seg)) return 'r2 sessions refuse resizing the file';
    if (/^(L|T)\b/.test(seg) || /^(Ll|Lc|Lo)/.test(seg)) return 'r2 sessions refuse loading plugins';
    if (/^q/.test(seg)) return 'use bridge_session_close to end a session';
  }
  return undefined;
}

// ---------------- gdb ----------------

const GDB_DENY = [
  'shell', 'pipe', 'python', 'python-interactive', 'pi', 'py', 'guile', 'guile-repl', 'gu', 'gr', 'source', 'make', 'cd',
  'dump', 'append', 'restore', 'eval', 'alias', 'define', 'define-prefix', 'document', 'interpreter-exec', 'compile', 'jit-reader-load',
  'add-auto-load-safe-path', 'add-auto-load-scripts-directory', 'save', 'generate-core-file', 'gcore', 'edit', 'file', 'exec-file',
  'symbol-file', 'add-symbol-file', 'core-file', 'attach', 'quit', 'with', 'taas', 'faas', 'tfaas', 'tui',
  'target', 'maintenance', 'commands', 'while', 'if', 'end', 'document', 'new-ui', 'inferior', 'add-inferior', 'clone-inferior',
];
/** Allowed exact words that are also abbreviations of a denied word. */
const GDB_SAFE = new Set(['s', 'si', 'c', 'n', 'ni', 'p', 'x', 'i', 'b', 'bt', 'f', 'u', 'r', 'run', 'start', 'starti', 'info', 'inf']);
const GDB_SET_DENY = ['logging', 'startup-with-shell', 'exec-wrapper', 'auto-load', 'history', 'debuginfod', 'trace-commands', 'sysroot', 'solib-search-path', 'inferior-tty', 'remote', 'exec-file-mismatch', 'cwd', 'debug-file-directory', 'data-directory', 'python', 'guile', 'extension-language', 'script-extension', 'editing', 'prompt', 'confirm', 'pagination', 'width', 'height'];

/**
 * gdb console command (sent through MI). Refuses host escapes (shell, !, |, pipe, python, guile,
 * compile, source, $_shell), file writes (dump, save, gcore, set logging), target switching
 * (file, attach, target, core-file), command builders that could hide those (alias, define,
 * eval, with, apply, taas, faas), and settings that break the session (startup-with-shell,
 * exec-wrapper, prompt, pagination).
 */
export function checkGdbCommand(cmd: unknown): string | undefined {
  const b = basic(cmd);
  if (typeof b !== 'string') return b.error;
  if (/^[!|]/.test(b)) return 'gdb sessions refuse ! and | (host shell)';
  if (/\$_shell\b|\$_as_string\s*\(\s*\$_shell/.test(b)) return 'gdb sessions refuse $_shell';
  if (/\bapply\b/.test(b)) return 'gdb sessions refuse "apply" (it runs another command for every thread or frame)';
  if (b.startsWith('-')) return 'raw MI commands are not accepted; send console commands';
  const words = b.split(/\s+/);
  const tok = words[0]!.toLowerCase();
  if (!GDB_SAFE.has(tok)) {
    for (const d of GDB_DENY) if (abbreviates(tok, d)) return `gdb sessions refuse "${d}"`;
  }
  if (abbreviates(tok, 'set', 3) || tok === 'set') {
    const sub = (words[1] ?? '').toLowerCase();
    if (sub === 'var' || sub === 'variable' || sub.startsWith('$') || sub.startsWith('*') || /^\w+\s*=/.test(words.slice(1).join(' '))) {
      // set var x = 1 / set $r = 2 / set *(int*)0x1 = 3 change the target only
      return undefined;
    }
    for (const d of GDB_SET_DENY) if (sub && abbreviates(sub, d, 3)) return `gdb sessions refuse "set ${d}"`;
  }
  return undefined;
}

// ---------------- lldb ----------------

const LLDB_DENY = [
  'platform', 'script', 'command', 'shell', 'target', 'file', 'attach', 'detach', 'kill', 'quit', 'exit', 'log', 'plugin', 'gui',
  'session', 'trace', 'statistics', 'repl', 'swift-healthcheck',
];
const LLDB_SAFE = new Set(['s', 'si', 'c', 'n', 'ni', 'p', 'po', 'x', 'b', 'bt', 'f', 'r', 'run', 'up', 'down', 'v', 'th', 'thread', 'fr', 'frame', 'di', 'dis', 'disassemble', 're', 'register', 'me', 'memory', 'br', 'breakpoint', 'wa', 'watchpoint', 'pr', 'process', 'ty', 'type', 'im', 'image', 'expr', 'e', 'version', 'help', 'apropos', 'se', 'settings', 'finish', 'gdb-remote', 'kdp-remote', 'reg']);

/**
 * lldb command. Refuses host escapes (platform shell, script, command script/source/alias,
 * shell), file writes (memory read --outfile, log enable -f, process save-core), target
 * switching (target, file, attach), breakpoint and stop hook command lists that could hold any of
 * those, Python callbacks, and process launch with a shell.
 */
export function checkLldbCommand(cmd: unknown): string | undefined {
  const b = basic(cmd);
  if (typeof b !== 'string') return b.error;
  const words = b.split(/\s+/);
  const tok = words[0]!.toLowerCase();
  if (tok.startsWith('_') || tok.startsWith('!')) return 'lldb sessions refuse internal and ! commands';
  if (!LLDB_SAFE.has(tok)) {
    for (const d of LLDB_DENY) if (abbreviates(tok, d)) return `lldb sessions refuse "${d}"`;
  }
  for (const w of words) {
    if (/^--(python|script|shell|outfile|append-outfile|one-liner)/i.test(w)) return 'lldb sessions refuse python callbacks, one liners, shells and output files';
  }
  if (/^(br|breakpoint)\s+(set|s)\b.*\s(-P|--python-class)\b/.test(b)) return 'lldb sessions refuse scripted breakpoints';
  if (/\bstep-scripted\b/.test(b)) return 'lldb sessions refuse scripted steps';
  if (/^(pr|process)\s+(launch|la)\b.*\s(-c|-X)\b/.test(b)) return 'lldb sessions refuse launching through a shell';
  if (/^(br|breakpoint|wa|watchpoint)\b.*\bcommand\b/.test(b) || /\bstop-hook\b/.test(b)) return 'lldb sessions refuse breakpoint and stop hook command lists';
  if (/^(pr|process)\s+(save-core|launch\s+.*-c|plugin|connect|attach)\b/.test(b)) return 'lldb sessions refuse that process subcommand';
  if (/^(se|settings)\b/.test(b) && !/^(se|settings)\s+(show|list)\b/.test(b)) {
    // settings set changes how lldb behaves (prompt, script language, launch shell); only reading is allowed
    if (!/^(se|settings)\s+set\s+(target\.(run-args|env-vars|disable-aslr|max-children-count|max-string-summary-length)|stop-disassembly-count|stop-line-count-before|stop-line-count-after)\b/.test(b)) {
      return 'lldb sessions only allow settings show, list and a few safe settings set keys';
    }
  }
  if (/^(im|image|ta|target)\s+(add|load|dump\s+symfile)/.test(b)) return 'lldb sessions refuse loading images';
  if (/^(ty|type)\s+(summary|synthetic|format|filter)\s+add\b.*(-P|--python|-F)/.test(b)) return 'lldb sessions refuse python formatters';
  if (/^(me|memory|x)\b.*\s-o\b/.test(b) || /^(me|memory)\s+(read|find|save)\b.*\s(-o)\b/.test(b)) return 'lldb sessions refuse writing memory to files';
  return undefined;
}

/** Quote a string as a C string for gdb MI (-interpreter-exec console "..."). */
export function miQuote(s: string): string {
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}
