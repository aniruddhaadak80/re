import { Highlight, type PrismTheme } from 'prism-react-renderer';
import { CopyButton } from './ui';

/** Gold and teal code theme. No purple or pink tokens. */
export const LENS_THEME: PrismTheme = {
  plain: { color: '#EDEAE0', backgroundColor: '#0F0F11' },
  styles: [
    { types: ['comment', 'prolog', 'doctype', 'cdata'], style: { color: '#7D796E', fontStyle: 'italic' } },
    { types: ['punctuation', 'operator'], style: { color: '#B9B5A9' } },
    { types: ['keyword', 'selector', 'important', 'atrule', 'rule'], style: { color: '#F5B301' } },
    { types: ['string', 'char', 'attr-value', 'inserted', 'regex'], style: { color: '#5EEAD4' } },
    { types: ['number', 'boolean', 'constant', 'symbol'], style: { color: '#FDBA74' } },
    { types: ['function', 'class-name', 'builtin'], style: { color: '#FFD166' } },
    { types: ['property', 'tag', 'attr-name', 'variable'], style: { color: '#7DD3FC' } },
    { types: ['deleted'], style: { color: '#FCA5A5' } },
  ],
};

const ALIAS: Record<string, string> = { sh: 'bash', shell: 'bash', console: 'bash', zsh: 'bash', yml: 'yaml', ts: 'tsx', typescript: 'tsx', js: 'jsx', javascript: 'jsx', mjs: 'jsx', cjs: 'jsx', jsonc: 'json', yara: 'cpp' };

export function CodeBlock({ code, lang = '', title }: { code: string; lang?: string; title?: string }) {
  const language = ALIAS[lang] ?? (lang || 'text');
  return (
    <div className="group relative my-5 overflow-hidden rounded-xl border border-line bg-[#0F0F11]">
      <div className="flex items-center justify-between gap-2 border-b border-white/10 px-3 py-1.5">
        <span className="truncate font-mono text-[11px] uppercase tracking-wider text-[#A39F94]">{title ?? (lang || 'text')}</span>
        <CopyButton text={code} className="!border-white/10 !bg-white/5 !text-[#C9C5BA]" />
      </div>
      <Highlight code={code.replace(/\n$/, '')} language={language} theme={LENS_THEME}>
        {({ className, style, tokens, getLineProps, getTokenProps }) => (
          <pre className={`${className} overflow-x-auto p-4 text-[13px] leading-6`} style={{ ...style, background: 'transparent' }}>
            {tokens.map((line, i) => (
              <div key={i} {...getLineProps({ line })}>
                {line.map((token, k) => <span key={k} {...getTokenProps({ token })} />)}
              </div>
            ))}
          </pre>
        )}
      </Highlight>
    </div>
  );
}
