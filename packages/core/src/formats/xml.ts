// A small, bounded XML reader for package manifests (plist, xar TOC, AppxManifest, PackageInfo).
// Linear scanner, no regular expressions on the input, caps on nodes, depth and text size.
// It is not a validating parser: it reads well formed documents and stops quietly on broken ones.

export interface XmlNode {
  /** qualified name as written, for example "uap:VisualElements" */
  name: string;
  /** name without a namespace prefix */
  local: string;
  attrs: Record<string, string>;
  children: XmlNode[];
  /** concatenated direct text content, entities decoded */
  text: string;
}

export interface XmlLimits { maxNodes?: number; maxDepth?: number; maxText?: number }

const ENT: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

/** Decode the five XML entities and numeric character references. Unknown entities stay as written. */
export function decodeEntities(s: string): string {
  if (s.indexOf('&') < 0) return s;
  let out = '';
  let i = 0;
  while (i < s.length) {
    const amp = s.indexOf('&', i);
    if (amp < 0) { out += s.slice(i); break; }
    out += s.slice(i, amp);
    const semi = s.indexOf(';', amp);
    if (semi < 0 || semi - amp > 12) { out += '&'; i = amp + 1; continue; }
    const ent = s.slice(amp + 1, semi);
    let rep: string | undefined;
    if (ent.startsWith('#x') || ent.startsWith('#X')) { const n = parseInt(ent.slice(2), 16); if (Number.isFinite(n) && n >= 0 && n <= 0x10ffff) rep = String.fromCodePoint(n); }
    else if (ent.startsWith('#')) { const n = parseInt(ent.slice(1), 10); if (Number.isFinite(n) && n >= 0 && n <= 0x10ffff) rep = String.fromCodePoint(n); }
    else rep = ENT[ent];
    if (rep === undefined) { out += s.slice(amp, semi + 1); } else out += rep;
    i = semi + 1;
  }
  return out;
}

function isNameChar(c: number): boolean {
  return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x5f || c === 0x3a || c === 0x2d || c === 0x2e || c > 0x7f;
}
function isSpace(c: number): boolean { return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d; }

/** Parse an XML document into a tree. Returns a synthetic root named "#document". */
export function parseXml(src: string, limits: XmlLimits = {}): XmlNode {
  const maxNodes = limits.maxNodes ?? 200_000;
  const maxDepth = limits.maxDepth ?? 128;
  const maxText = limits.maxText ?? 16 * 1024 * 1024;
  const root: XmlNode = { name: '#document', local: '#document', attrs: {}, children: [], text: '' };
  const stack: XmlNode[] = [root];
  let nodes = 0;
  let i = 0;
  const n = src.length;
  const top = (): XmlNode => stack[stack.length - 1] as XmlNode;
  const addText = (t: string): void => { const cur = top(); if (cur.text.length + t.length <= maxText) cur.text += t; };
  while (i < n) {
    const lt = src.indexOf('<', i);
    if (lt < 0) { if (stack.length > 1) addText(decodeEntities(src.slice(i))); break; }
    if (lt > i && stack.length > 1) addText(decodeEntities(src.slice(i, lt)));
    if (src.startsWith('<!--', lt)) { const e = src.indexOf('-->', lt + 4); i = e < 0 ? n : e + 3; continue; }
    if (src.startsWith('<![CDATA[', lt)) { const e = src.indexOf(']]>', lt + 9); const end = e < 0 ? n : e; if (stack.length > 1) addText(src.slice(lt + 9, end)); i = e < 0 ? n : e + 3; continue; }
    if (src.startsWith('<?', lt)) { const e = src.indexOf('?>', lt + 2); i = e < 0 ? n : e + 2; continue; }
    if (src.startsWith('<!', lt)) {
      // DOCTYPE, possibly with an internal subset in brackets. Skip without expanding anything.
      let j = lt + 2, depth = 0;
      while (j < n) { const c = src.charCodeAt(j); if (c === 0x5b) depth++; else if (c === 0x5d) depth--; else if (c === 0x3e && depth <= 0) break; j++; }
      i = j + 1; continue;
    }
    if (src.charCodeAt(lt + 1) === 0x2f) { // closing tag
      const gt = src.indexOf('>', lt + 2);
      const name = src.slice(lt + 2, gt < 0 ? n : gt).trim();
      // Pop to the matching element; ignore a stray close tag.
      for (let k = stack.length - 1; k > 0; k--) { if ((stack[k] as XmlNode).name === name) { stack.length = k; break; } }
      i = gt < 0 ? n : gt + 1; continue;
    }
    // opening tag
    let j = lt + 1;
    while (j < n && isNameChar(src.charCodeAt(j))) j++;
    const name = src.slice(lt + 1, j);
    if (!name) { addText('<'); i = lt + 1; continue; }
    const attrs: Record<string, string> = Object.create(null) as Record<string, string>;
    let selfClose = false;
    for (;;) {
      while (j < n && isSpace(src.charCodeAt(j))) j++;
      if (j >= n) break;
      const c = src.charCodeAt(j);
      if (c === 0x3e) { j++; break; }
      if (c === 0x2f && src.charCodeAt(j + 1) === 0x3e) { selfClose = true; j += 2; break; }
      const as = j;
      while (j < n && isNameChar(src.charCodeAt(j))) j++;
      const an = src.slice(as, j);
      if (!an) { j++; continue; }
      while (j < n && isSpace(src.charCodeAt(j))) j++;
      if (src.charCodeAt(j) !== 0x3d) { attrs[an] = ''; continue; }
      j++;
      while (j < n && isSpace(src.charCodeAt(j))) j++;
      const q = src.charCodeAt(j);
      if (q === 0x22 || q === 0x27) {
        const e = src.indexOf(q === 0x22 ? '"' : "'", j + 1);
        const end = e < 0 ? n : e;
        attrs[an] = decodeEntities(src.slice(j + 1, end));
        j = end + 1;
      } else {
        const vs = j;
        while (j < n && !isSpace(src.charCodeAt(j)) && src.charCodeAt(j) !== 0x3e) j++;
        attrs[an] = decodeEntities(src.slice(vs, j));
      }
    }
    if (++nodes > maxNodes) break;
    const colon = name.indexOf(':');
    const node: XmlNode = { name, local: colon >= 0 ? name.slice(colon + 1) : name, attrs: { ...attrs }, children: [], text: '' };
    top().children.push(node);
    if (!selfClose && stack.length <= maxDepth) stack.push(node);
    i = j;
  }
  return root;
}

/** First child element with this local name. */
export function child(n: XmlNode | undefined, local: string): XmlNode | undefined {
  return n?.children.find((c) => c.local === local);
}
/** Every child element with this local name. */
export function childrenNamed(n: XmlNode | undefined, local: string): XmlNode[] {
  return n ? n.children.filter((c) => c.local === local) : [];
}
/** Depth first search for every element with this local name, capped. */
export function findAll(n: XmlNode, local: string, cap = 100_000): XmlNode[] {
  const out: XmlNode[] = [];
  const stack: XmlNode[] = [n];
  while (stack.length && out.length < cap) {
    const cur = stack.pop() as XmlNode;
    if (cur.local === local) out.push(cur);
    for (let k = cur.children.length - 1; k >= 0; k--) stack.push(cur.children[k] as XmlNode);
  }
  return out;
}
/** First element with this local name anywhere below n. */
export function findFirst(n: XmlNode, local: string): XmlNode | undefined { return findAll(n, local, 1)[0]; }
