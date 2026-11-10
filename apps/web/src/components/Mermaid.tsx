import { useEffect, useId, useState } from 'react';
import DOMPurify from 'dompurify';
import { useSettings, resolvedTheme } from '../lib/settings';
import { CodeBlock } from './CodeBlock';

type MermaidApi = typeof import('mermaid').default;
let loader: Promise<MermaidApi> | null = null;
const load = () => (loader ??= import('mermaid').then((m) => m.default));

/**
 * Mermaid already renders with securityLevel strict, and its output is sanitized once more here
 * before it reaches the DOM, so a hostile diagram in docs or a pasted report cannot run script.
 * foreignObject stays because mermaid draws HTML labels inside it; scripts and handlers do not.
 */
export function cleanSvg(svg: string): string {
  return DOMPurify.sanitize(svg, {
    USE_PROFILES: { svg: true, svgFilters: true, html: true },
    ADD_TAGS: ['foreignObject'],
    HTML_INTEGRATION_POINTS: { foreignobject: true },
    FORBID_TAGS: ['script', 'iframe', 'object', 'embed'],
    FORBID_ATTR: ['xlink:href'],
  });
}

/** Renders a mermaid diagram client side. The library loads only when a diagram is on screen. */
export function Mermaid({ code }: { code: string }) {
  const s = useSettings();
  const light = resolvedTheme(s.theme) === 'sun';
  const raw = useId().replace(/[^a-zA-Z0-9]/g, '');
  const [svg, setSvg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    load().then(async (mermaid) => {
      const gold = '#F5B301', teal = '#14B8A6';
      mermaid.initialize({
        startOnLoad: false, securityLevel: 'strict', theme: 'base', fontFamily: 'Inter, system-ui, sans-serif',
        themeVariables: {
          background: light ? '#FFFFFF' : '#111113',
          primaryColor: light ? '#FFF6DA' : '#1E1A0E', primaryTextColor: light ? '#1A1814' : '#F2EFE6', primaryBorderColor: gold,
          secondaryColor: light ? '#DDF6F2' : '#0E1F1D', secondaryTextColor: light ? '#1A1814' : '#F2EFE6', secondaryBorderColor: teal,
          tertiaryColor: light ? '#F4F2EB' : '#1A1A1D', tertiaryTextColor: light ? '#1A1814' : '#F2EFE6', tertiaryBorderColor: light ? '#E0DCCF' : '#38373E',
          lineColor: teal, textColor: light ? '#1A1814' : '#F2EFE6', mainBkg: light ? '#FFF6DA' : '#1E1A0E', nodeBorder: gold,
          clusterBkg: light ? '#FAF9F5' : '#151517', clusterBorder: light ? '#E0DCCF' : '#38373E', edgeLabelBackground: light ? '#FFFFFF' : '#111113',
          actorBkg: light ? '#FFF6DA' : '#1E1A0E', actorBorder: gold, actorTextColor: light ? '#1A1814' : '#F2EFE6', signalColor: teal, signalTextColor: light ? '#1A1814' : '#F2EFE6',
          noteBkgColor: light ? '#DDF6F2' : '#0E1F1D', noteBorderColor: teal, noteTextColor: light ? '#1A1814' : '#F2EFE6',
          pie1: gold, pie2: teal, pie3: '#FFD166', pie4: '#0EA5E9', pie5: '#F97316', pie6: '#10B981', pie7: '#A3A3A3', pie8: '#FDE68A',
          git0: gold, git1: teal, git2: '#0EA5E9', git3: '#F97316', git4: '#10B981', git5: '#FFD166', git6: '#5EEAD4', git7: '#A3A3A3',
        },
      });
      try {
        const { svg } = await mermaid.render(`m${raw}${light ? 'l' : 'd'}`, code.trim());
        if (alive) { setSvg(cleanSvg(svg)); setErr(null); }
      } catch (e) { if (alive) setErr((e as Error).message); }
    }).catch((e: Error) => alive && setErr(e.message));
    return () => { alive = false; };
  }, [code, light, raw]);
  if (err) return <div><p className="text-xs text-muted">This diagram could not be drawn, so here is its source.</p><CodeBlock code={code} lang="mermaid" /></div>;
  if (!svg) return <div className="my-6 h-40 animate-pulse rounded-xl border border-line bg-surface2" aria-label="Loading diagram" />;
  return <div className="mermaid-diagram my-6 overflow-x-auto rounded-xl border border-line bg-surface p-4 [&_svg]:mx-auto [&_svg]:h-auto [&_svg]:max-w-full" dangerouslySetInnerHTML={{ __html: svg }} />;
}
