// Docs, blog posts and the changelog are read from the repo at build time.
// If a folder is empty the globs return nothing and the pages show an empty state.
import { slugify } from './util';

const docFiles = import.meta.glob(['../../../../docs/*.md', '../../../../docs/showcases/*.md', '!../../../../docs/showcases/README.md'], { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
const blogFiles = import.meta.glob('../../../../content/blog/*.md', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
const changelogFiles = import.meta.glob('../../../../CHANGELOG.md', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;

export interface Heading { depth: number; text: string; id: string }
export interface Doc { slug: string; title: string; description: string; body: string; order: number; headings: Heading[]; words: number }
export interface Post extends Doc { date: string; summary: string; tags: string[]; cover?: string; readingMinutes: number }

export function parseFrontmatter(src: string): { data: Record<string, string | string[]>; body: string } {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(src);
  if (!m) return { data: {}, body: src };
  const data: Record<string, string | string[]> = {};
  let listKey: string | null = null;
  for (const line of (m[1] ?? '').split(/\r?\n/)) {
    const item = /^\s*-\s+(.*)$/.exec(line);
    if (item && listKey) { (data[listKey] as string[]).push(unq(item[1] ?? '')); continue; }
    const kv = /^([\w-]+):\s*(.*)$/.exec(line);
    if (!kv) continue;
    const key = kv[1] as string, val = (kv[2] ?? '').trim();
    if (val === '') { data[key] = []; listKey = key; continue; }
    listKey = null;
    if (val.startsWith('[') && val.endsWith(']')) data[key] = val.slice(1, -1).split(',').map((s) => unq(s.trim())).filter(Boolean);
    else data[key] = unq(val);
  }
  return { data, body: src.slice(m[0].length) };
}
const unq = (s: string) => s.replace(/^["']|["']$/g, '');
const str = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v.join(', ') : v);

export function extractHeadings(md: string): Heading[] {
  const out: Heading[] = [];
  let inCode = false;
  for (const line of md.split(/\r?\n/)) {
    if (/^\s*(```|~~~)/.test(line)) { inCode = !inCode; continue; }
    if (inCode) continue;
    const m = /^(#{2,3})\s+(.+?)\s*#*\s*$/.exec(line);
    if (m) { const text = (m[2] ?? '').replace(/[`*_]/g, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1'); out.push({ depth: (m[1] ?? '').length, text, id: slugify(text) }); }
  }
  return out;
}

function firstParagraph(md: string): string {
  const p = md.split(/\r?\n\r?\n/).map((s) => s.trim()).find((s) => s && !/^(#|```|<|!\[|\||>|-|\*|\d+\.)/.test(s));
  return (p ?? '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1').replace(/[`*_]/g, '').replace(/\s+/g, ' ').slice(0, 200);
}

function toDoc(path: string, raw: string): Doc {
  const file = path.split('/').pop()!.replace(/\.md$/, '');
  const { data, body } = parseFrontmatter(raw);
  const h1 = /^#\s+(.+)$/m.exec(body);
  const title = str(data.title) ?? h1?.[1]?.trim() ?? file.replace(/[-_]/g, ' ');
  const orderMatch = /^(\d+)[-_]/.exec(file);
  // Showcases sit after the reference pages.
  const base = path.includes('/showcases/') ? 40 : 0;
  const order = base + Number(str(data.order) ?? orderMatch?.[1] ?? (file === 'index' || file === 'getting-started' ? -1 : 500));
  const words = body.split(/\s+/).filter(Boolean).length;
  return { slug: file, title, description: str(data.description) ?? firstParagraph(body.replace(/^#\s+.+$/m, '')), body, order, headings: extractHeadings(body), words };
}

export const DOCS: Doc[] = Object.entries(docFiles).map(([p, raw]) => toDoc(p, raw))
  .sort((a, b) => a.order - b.order || a.title.localeCompare(b.title));

export const POSTS: Post[] = Object.entries(blogFiles).map(([p, raw]) => {
  const d = toDoc(p, raw);
  const { data } = parseFrontmatter(raw);
  const tags = data.tags ? (Array.isArray(data.tags) ? data.tags : data.tags.split(',').map((s) => s.trim())) : [];
  return { ...d, date: str(data.date) ?? '', summary: str(data.summary) ?? d.description, tags, cover: str(data.cover), readingMinutes: Math.max(1, Math.round(d.words / 220)) };
}).sort((a, b) => b.date.localeCompare(a.date) || a.title.localeCompare(b.title));

export const CHANGELOG: string | null = Object.values(changelogFiles)[0] ?? null;

/** Resolve a relative asset path used inside a markdown file to the copied public URL. */
export function assetUrl(src: string, from: 'docs' | 'blog'): string {
  if (/^(https?:|data:|\/\/)/.test(src)) return src;
  if (src.startsWith('/')) return src;
  const clean = src.replace(/^\.\//, '').replace(/^\.\.\/\.\.\/docs\//, '').replace(/^\.\.\/docs\//, '');
  return `${import.meta.env.BASE_URL}content/${from}/${clean}`;
}

export function formatDate(d: string): string {
  const t = Date.parse(d);
  return Number.isNaN(t) ? d : new Date(t).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
}
