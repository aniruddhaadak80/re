// After vite build: write one index.html per route (so deep links return 200 on GitHub Pages),
// a 404.html, sitemap.xml and robots.txt. Each copy gets its own title, description and OG tags.
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const web = join(here, '..');
const repo = join(web, '..', '..');
const dist = join(web, 'dist');
const base = process.env.BASE ?? '/re/';
const site = (process.env.SITE_URL ?? 'https://aniruddhaadak80.github.io').replace(/\/$/, '');
const routes = JSON.parse(readFileSync(join(web, 'src', 'routes.json'), 'utf8'));

const fm = (src) => {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(src);
  const out = {};
  if (m) for (const line of m[1].split(/\r?\n/)) { const kv = /^(\w+):\s*(.*)$/.exec(line); if (kv) out[kv[1]] = kv[2].replace(/^["']|["']$/g, ''); }
  const h1 = /^#\s+(.+)$/m.exec(src.replace(/^---[\s\S]*?---/, ''));
  if (!out.title && h1) out.title = h1[1].trim();
  return out;
};
const firstPara = (src) => {
  const body = src.replace(/^---[\s\S]*?---/, '').split(/\r?\n\r?\n/).map((p) => p.trim()).find((p) => p && !p.startsWith('#') && !p.startsWith('```') && !p.startsWith('<') && !p.startsWith('!') && !p.startsWith('|'));
  return (body ?? '').replace(/[`*_\[\]]/g, '').replace(/\(([^)]*)\)/g, '').replace(/\s+/g, ' ').slice(0, 180);
};
const mdIn = (dir) => (existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith('.md')) : []);

for (const f of mdIn(join(repo, 'docs'))) {
  const src = readFileSync(join(repo, 'docs', f), 'utf8');
  const meta = fm(src);
  routes[`/docs/${f.replace(/\.md$/, '')}`] = { title: `${meta.title ?? f} | RevLens docs`, description: meta.description ?? (firstPara(src) || routes['/docs'].description) };
}
for (const f of mdIn(join(repo, 'content', 'blog'))) {
  const src = readFileSync(join(repo, 'content', 'blog', f), 'utf8');
  const meta = fm(src);
  routes[`/blog/${f.replace(/\.md$/, '')}`] = { title: `${meta.title ?? f} | RevLens blog`, description: meta.summary ?? (firstPara(src) || routes['/blog'].description) };
}

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
const html = readFileSync(join(dist, 'index.html'), 'utf8');
const page = (path, meta) => {
  const url = `${site}${base}${path.replace(/^\//, '')}`;
  return html
    .replace(/<title>[\s\S]*?<\/title>/, `<title>${esc(meta.title)}</title>`)
    .replace(/(<meta name="description" content=")[^"]*(")/, `$1${esc(meta.description)}$2`)
    .replace(/(<meta property="og:title" content=")[^"]*(")/, `$1${esc(meta.title)}$2`)
    .replace(/(<meta property="og:description" content=")[^"]*(")/, `$1${esc(meta.description)}$2`)
    .replace(/(<meta property="og:url" content=")[^"]*(")/, `$1${esc(url)}$2`)
    .replace(/(<meta name="twitter:title" content=")[^"]*(")/, `$1${esc(meta.title)}$2`)
    .replace(/(<meta name="twitter:description" content=")[^"]*(")/, `$1${esc(meta.description)}$2`)
    .replace(/(<link rel="canonical" href=")[^"]*(")/, `$1${esc(url)}$2`);
};

let n = 0;
for (const [path, meta] of Object.entries(routes)) {
  const out = path === '/' ? join(dist, 'index.html') : join(dist, path.slice(1), 'index.html');
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, page(path, meta));
  n++;
}
writeFileSync(join(dist, '404.html'), page('/404', { title: 'Page not found | RevLens', description: 'This page does not exist. Try the analyzer, the docs or the blog.' }).replace('<head>', '<head>\n    <meta name="robots" content="noindex">'));

const today = new Date().toISOString().slice(0, 10);
const urls = Object.keys(routes).filter((p) => p !== '/settings');
writeFileSync(join(dist, 'sitemap.xml'), `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map((p) => `  <url><loc>${site}${base}${p === '/' ? '' : p.slice(1) + '/'}</loc><lastmod>${today}</lastmod></url>`).join('\n')}\n</urlset>\n`);
writeFileSync(join(dist, 'robots.txt'), `User-agent: *\nAllow: /\n\nSitemap: ${site}${base}sitemap.xml\n`);
writeFileSync(join(dist, '.nojekyll'), '');
console.log(`[postbuild] wrote ${n} route pages, 404.html, sitemap.xml (${urls.length} urls), robots.txt`);
