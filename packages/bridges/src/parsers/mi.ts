// gdb/MI output parsing (the machine interface gdb speaks with --interpreter=mi3). Pure, browser safe.

/** Decode an MI C string body (without the outer quotes): \n \t \" \\ and \ooo octal escapes. */
export function miUnquote(body: string): string {
  let out = '';
  for (let i = 0; i < body.length; i++) {
    const c = body[i]!;
    if (c !== '\\' || i + 1 >= body.length) { out += c; continue; }
    const n = body[++i]!;
    if (n === 'n') out += '\n';
    else if (n === 't') out += '\t';
    else if (n === 'r') out += '\r';
    else if (n === 'e') out += '\x1b';
    else if (n >= '0' && n <= '7') {
      let oct = n;
      while (oct.length < 3 && i + 1 < body.length && body[i + 1]! >= '0' && body[i + 1]! <= '7') oct += body[++i]!;
      out += String.fromCharCode(parseInt(oct, 8));
    } else out += n;
  }
  return out;
}

/** Read the C string that starts at s[start] === '"'. Returns the decoded text and the index after the closing quote. */
export function miReadString(s: string, start: number): { value: string; end: number } | undefined {
  if (s[start] !== '"') return undefined;
  let i = start + 1;
  while (i < s.length) {
    if (s[i] === '\\') { i += 2; continue; }
    if (s[i] === '"') return { value: miUnquote(s.slice(start + 1, i)), end: i + 1 };
    i++;
  }
  return undefined;
}

/** Pull simple key="value" pairs out of an MI result line (nested tuples flattened, first wins). */
export function miFields(line: string, maxFields = 200): Record<string, string> {
  const out: Record<string, string> = {};
  let n = 0;
  const re = /([a-z][\w-]{0,63})="/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line)) && n < maxFields) {
    const str = miReadString(line, m.index + m[0].length - 1);
    if (!str) break;
    if (!(m[1]! in out)) { out[m[1]!] = str.value.slice(0, 4096); n++; }
    re.lastIndex = str.end;
  }
  return out;
}

export interface MiReply {
  /** console stream (~): what the command printed */
  console: string;
  /** target stream (@) plus lines that are not MI at all: the program's own output */
  target: string;
  /** log stream (&): gdb's echo of the command and warnings */
  log: string;
  /** result class of the tokened record: done, running, connected, error, exit */
  result?: string;
  error?: string;
  /** last *stopped record: reason, frame function, address, signal, exit code */
  stopped?: Record<string, string>;
  /** async notifications (=breakpoint-created and so on), capped */
  notify: string[];
}

/** Split a chunk of MI output (complete lines) into streams and records. */
export function parseMiLines(text: string, token?: string): MiReply {
  const r: MiReply = { console: '', target: '', log: '', notify: [] };
  for (const line of text.split(/\r?\n/)) {
    if (!line || line === '(gdb) ' || line === '(gdb)') continue;
    const c = line[0];
    if (c === '~' || c === '@' || c === '&') {
      const s = miReadString(line, 1);
      if (!s) continue;
      if (c === '~') r.console += s.value;
      else if (c === '@') r.target += s.value;
      else r.log += s.value;
      continue;
    }
    const tm = /^(\d*)\^(done|running|connected|error|exit)(,.*)?$/.exec(line);
    if (tm) {
      if (token === undefined || tm[1] === token) {
        r.result = tm[2];
        if (tm[2] === 'error') r.error = miFields(tm[3] ?? '').msg ?? 'error';
      }
      continue;
    }
    if (line.startsWith('*stopped')) { r.stopped = miFields(line); continue; }
    if (line.startsWith('*running')) continue;
    if (line.startsWith('=')) { if (r.notify.length < 200) r.notify.push(line.slice(0, 2000)); continue; }
    if (/^\d*[\^*+=]/.test(line)) continue;
    r.target += line + '\n';
  }
  return r;
}
