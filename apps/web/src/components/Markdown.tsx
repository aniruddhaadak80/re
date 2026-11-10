import { Children, isValidElement, type ReactNode } from 'react';
import ReactMarkdown, { type Components } from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Link } from 'react-router-dom';
import { CodeBlock } from './CodeBlock';
import { Mermaid } from './Mermaid';
import { assetUrl } from '../lib/content';
import { slugify } from '../lib/util';

function textOf(n: ReactNode): string {
  if (typeof n === 'string' || typeof n === 'number') return String(n);
  if (Array.isArray(n)) return n.map(textOf).join('');
  if (isValidElement<{ children?: ReactNode }>(n)) return textOf(n.props.children);
  return '';
}

/** Turns simple raw <img> tags outside code fences into markdown images, since raw HTML is not rendered. */
function normalize(md: string): string {
  let fence = false;
  return md.split('\n').map((line) => {
    if (/^\s*(```|~~~)/.test(line)) { fence = !fence; return line; }
    if (fence) return line;
    return line.replace(/<img\s+([^>]*?)\/?>/g, (_, attrs: string) => {
      const src = /src="([^"]+)"/.exec(attrs)?.[1];
      const alt = /alt="([^"]*)"/.exec(attrs)?.[1] ?? '';
      return src ? `![${alt}](${src})` : '';
    });
  }).join('\n');
}

/** Markdown with GFM, gold and teal code, mermaid diagrams and heading anchors. */
export function Markdown({ source, from }: { source: string; from: 'docs' | 'blog' | 'root' }) {
  const heading = (Tag: 'h2' | 'h3' | 'h4') => ({ children }: { children?: ReactNode }) => {
    const id = slugify(textOf(children));
    return <Tag id={id} className="group">{children}<a href={`#${id}`} aria-label="Link to this section" className="ml-2 text-muted opacity-0 no-underline transition group-hover:opacity-100">#</a></Tag>;
  };
  const components: Components = {
    h2: heading('h2'), h3: heading('h3'), h4: heading('h4'),
    pre: ({ children }) => <>{children}</>,
    code: ({ className, children }) => {
      const lang = /language-([\w-]+)/.exec(className ?? '')?.[1];
      const code = String(Children.toArray(children).join(''));
      if (!lang && !code.includes('\n')) return <code>{children}</code>;
      if (lang === 'mermaid') return <Mermaid code={code} />;
      return <CodeBlock code={code} lang={lang} />;
    },
    a: ({ href = '', children }) => {
      const md = /^(?:\.\/)?(?:\.\.\/docs\/|docs\/)?([\w-]+)\.md(#.*)?$/.exec(href);
      if (md && from !== 'root') return <Link to={`/${from === 'blog' && !href.includes('docs') ? 'blog' : 'docs'}/${md[1]}${md[2] ?? ''}`}>{children}</Link>;
      if (href.startsWith('#')) return <a href={href}>{children}</a>;
      return <a href={href} target="_blank" rel="noreferrer">{children}</a>;
    },
    img: ({ src = '', alt = '' }) => <img src={from === 'root' ? src : assetUrl(String(src), from)} alt={alt} loading="lazy" />,
    table: ({ children }) => <table>{children}</table>,
  };
  return <div className="prose-rl"><ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>{normalize(source)}</ReactMarkdown></div>;
}
