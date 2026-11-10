import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Activity, ArrowRight, Binary, Boxes, Braces, Check, Cpu, FileArchive, FileSearch, Fingerprint, FlaskConical, Globe, KeyRound,
  Layers, Lock, Map as MapIcon, Minus, Package, Puzzle, Radar, ScanSearch, ShieldAlert, Terminal, Wand2, Zap,
} from 'lucide-react';
import { ANALYZERS } from '@revlens/core';
import { LensHero } from '../components/LensHero';
import { FlowDiagram } from '../components/FlowDiagram';
import { DropZone } from '../components/DropZone';
import { CodeBlock } from '../components/CodeBlock';
import { Section } from '../components/ui';
import { SAMPLES } from '../lib/samples';
import { openFiles, openSample } from '../lib/actions';
import { useRouteSeo } from '../lib/seo';
import { useReducedMotionSetting } from '../lib/settings';
import { cx } from '../lib/util';

const ICONS: Record<string, typeof Binary> = {
  elf: Binary, pe: Cpu, macho: Layers, wasm: Braces, buildinfo: Fingerprint, entropy: Activity, strings: FileSearch,
  archive: FileArchive, 'ext-audit': Puzzle, 'bundle-sbom': Boxes, sourcemap: MapIcon, secrets: KeyRound, surface: Globe,
  'capa-lite': Radar, 'yara-lite': ShieldAlert,
};

type Mark = 'yes' | 'no' | 'some';
const TOOLS = ['RevLens', 'Ghidra MCP', 'IDA MCP', 'REA', 'r2mcp'];
const ROWS: { label: string; v: Mark[]; note?: string }[] = [
  { label: 'Works with nothing installed', v: ['yes', 'no', 'no', 'no', 'no'] },
  { label: 'Runs fully in the browser', v: ['yes', 'no', 'no', 'no', 'no'] },
  { label: 'Decompiler and deep native analysis', v: ['no', 'yes', 'yes', 'yes', 'some'] },
  { label: 'Debugging and dynamic analysis', v: ['no', 'some', 'some', 'some', 'yes'] },
  { label: 'SBOM from bundles and binaries', v: ['yes', 'no', 'no', 'some', 'no'] },
  { label: 'Secrets scanning with redaction', v: ['yes', 'no', 'no', 'no', 'no'] },
  { label: 'Extension and package audits', v: ['yes', 'no', 'no', 'some', 'no'] },
  { label: 'Release diff between versions', v: ['yes', 'some', 'some', 'some', 'some'] },
  { label: 'SARIF for code scanning', v: ['yes', 'no', 'no', 'no', 'no'] },
  { label: 'MCP server for agents', v: ['yes', 'yes', 'yes', 'yes', 'yes'] },
  { label: 'Free and open source', v: ['yes', 'yes', 'no', 'yes', 'yes'], note: 'IDA itself is commercial.' },
];

function MarkCell({ m }: { m: Mark }) {
  if (m === 'yes') return <Check size={16} className="mx-auto text-teal" aria-label="Yes" />;
  if (m === 'some') return <span className="mx-auto block w-fit rounded-full border border-accent/40 px-1.5 text-[10px] font-semibold uppercase text-ink">Partly</span>;
  return <Minus size={16} className="mx-auto text-muted/60" aria-label="No" />;
}

const CLI = `# analyze anything, no install needed
npx revlens analyze ./app.exe

# SBOM, SARIF and a release diff
npx revlens sbom ./dist/main.js > sbom.cdx.json
npx revlens sarif ./build.tgz --out revlens.sarif
npx revlens diff ./app-1.2.0.vsix ./app-1.3.0.vsix

# check a claim against the bytes
npx revlens verify ./ls "import=getenv"`;

const MCP = `{
  "mcpServers": {
    "revlens": {
      "command": "npx",
      "args": ["-y", "@revlens/mcp"]
    }
  }
}`;

export default function Home() {
  useRouteSeo('/');
  const nav = useNavigate();
  const reduced = useReducedMotionSetting();
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const runSample = async (id: string) => {
    const s = SAMPLES.find((x) => x.id === id)!;
    setBusy(id); setErr(null);
    try { await openSample(s); nav('/analyze'); } catch (e) { setErr((e as Error).message); } finally { setBusy(null); }
  };

  return (
    <div>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="grid-bg pointer-events-none absolute inset-0 opacity-40 [mask-image:radial-gradient(ellipse_at_center,black_20%,transparent_70%)]" />
        <div className="container-x relative grid grid-cols-1 items-center gap-10 py-14 sm:py-20 lg:grid-cols-[1.05fr_1fr] lg:py-24">
          <motion.div initial={reduced ? false : { opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
            <p className="chip mb-6 border-accent/40 text-ink"><Lock size={12} />Files never leave your device</p>
            <h1 className="text-4xl font-semibold leading-[1.05] tracking-tight sm:text-5xl lg:text-6xl">
              Look inside any <span className="text-gradient">binary, bundle or package.</span>
            </h1>
            <p className="mt-6 max-w-xl text-lg leading-8 text-muted">
              In your browser, your terminal, or your agent. RevLens is a zero-install reverse engineering lens for fast triage,
              supply chain checks and release diffs, written in plain TypeScript with no native dependencies.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link to="/analyze" className="btn-primary">Open the workspace <ArrowRight size={16} /></Link>
              <button type="button" className="btn-ghost" onClick={() => runSample('suspicious')} disabled={!!busy}><FlaskConical size={16} />Try the suspicious demo</button>
            </div>
            <div className="mt-8 flex flex-wrap gap-x-6 gap-y-2 text-sm text-muted">
              <span className="flex items-center gap-2"><Zap size={14} className="text-ink" />{ANALYZERS.length} analyzers</span>
              <span className="flex items-center gap-2"><Terminal size={14} className="text-ink" />CLI and MCP server</span>
              <span className="flex items-center gap-2"><Package size={14} className="text-ink" />SARIF and CycloneDX</span>
            </div>
          </motion.div>
          <LensHero />
        </div>
      </section>

      {/* Live drop zone and samples */}
      <section className="container-x" id="try">
        <div className="card relative overflow-hidden p-4 sm:p-6">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1.2fr_1fr]">
            <DropZone onFiles={async (f) => { await openFiles(f); nav('/analyze'); }} testId="home-file-input"
              title="Drop a file to analyze it right here" hint="ELF, PE, Mach-O, WASM, APK, JAR, CRX, XPI, VSIX, npm tgz, ASAR, JS bundles, source maps" />
            <div>
              <h2 className="text-lg font-semibold">Try a sample</h2>
              <p className="mt-1 text-sm text-muted">Real files from real projects, served from this site. The suspicious demo is built in your browser so its fake secrets never sit in the repository.</p>
              <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
                {SAMPLES.map((s) => (
                  <button key={s.id} type="button" onClick={() => runSample(s.id)} disabled={!!busy} data-testid={`sample-${s.id}`}
                    className={cx('group flex items-start gap-3 rounded-xl border border-line bg-surface2 p-3 text-left transition hover:-translate-y-0.5 hover:border-accent/60', busy === s.id && 'animate-pulse')}>
                    <span className={cx('mt-0.5 rounded-md px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase', s.id === 'suspicious' ? 'bg-red-500/15 text-red-600 dark:text-red-300' : 'bg-accent/15 text-ink')}>{s.kind}</span>
                    <span className="min-w-0"><span className="block truncate text-sm font-medium group-hover:text-ink">{s.label}</span><span className="block text-xs text-muted">{s.note}</span></span>
                  </button>
                ))}
              </div>
              {err && <p className="mt-3 text-sm text-red-500">{err}</p>}
            </div>
          </div>
        </div>
      </section>

      {/* Analyzers */}
      <Section id="analyzers" eyebrow="Analyzers" title="Every analyzer, one report"
        intro={<p>Each analyzer reads the bytes, adds what it can prove, and attaches evidence with offsets. They run together in a background worker, so a large file never freezes the page.</p>}>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {ANALYZERS.map((a, i) => {
            const Icon = ICONS[a.id] ?? ScanSearch;
            return (
              <motion.div key={a.id} id={`analyzer-${a.id}`} className="card card-hover group scroll-mt-24 p-5"
                initial={reduced ? false : { opacity: 0, y: 14 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, margin: '-30px' }} transition={{ delay: (i % 3) * 0.06 }}>
                <div className="flex items-center gap-3">
                  <div className="grid grid-cols-1 h-10 w-10 place-items-center rounded-xl border border-line bg-surface2 text-ink transition group-hover:border-accent/50 group-hover:bg-accent/10"><Icon size={18} /></div>
                  <div className="min-w-0"><p className="font-semibold">{a.title}</p><p className="font-mono text-[11px] text-muted">{a.id}</p></div>
                </div>
                <p className="mt-3 text-sm leading-6 text-muted">{a.description}</p>
              </motion.div>
            );
          })}
        </div>
      </Section>

      {/* Comparison */}
      <Section id="compare" eyebrow="Where it fits" title="Fast triage first, deep work where it belongs"
        intro={<><p>RevLens is the tool you reach for in the first five minutes: what is this file, what does it ship, what does it talk to, and did anything change since the last release. It needs nothing installed and it runs in a browser tab.</p><p className="mt-3">It is not a decompiler. When you need control flow, pseudocode or a debugger, hand the file to Ghidra, IDA, radare2 or REA. Those tools are excellent at deep native work, and RevLens is happy to be the step before them.</p></>}>
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[640px] text-sm">
            <thead>
              <tr className="border-b border-line">
                <th className="px-4 py-3 text-left font-medium text-muted">Capability</th>
                {TOOLS.map((t, i) => <th key={t} className={cx('px-3 py-3 text-center font-semibold', i === 0 && 'text-ink')}>{t}</th>)}
              </tr>
            </thead>
            <tbody>
              {ROWS.map((r) => (
                <tr key={r.label} className="border-b border-line/60 transition last:border-0 hover:bg-surface2/60">
                  <td className="px-4 py-3">{r.label}{r.note && <span className="block text-xs text-muted">{r.note}</span>}</td>
                  {r.v.map((m, i) => <td key={i} className={cx('px-3 py-3', i === 0 && 'bg-accent/5')}><MarkCell m={m} /></td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-xs text-muted">Based on each project's public documentation. Ghidra MCP and IDA MCP refer to community MCP bridges for those tools. Partly means it is possible with extra setup or plugins.</p>
      </Section>

      {/* How it works */}
      <Section id="how" eyebrow="How it works" title="From bytes to evidence in one pass"
        intro={<p>The same pure TypeScript core powers the web app, the command line and the MCP server. There is no server in the middle, so what you see here is exactly what your agent gets.</p>}>
        <FlowDiagram />
      </Section>

      {/* Install */}
      <Section id="install" eyebrow="Use it anywhere" title="Terminal and agents"
        intro={<p>Run the CLI with npx, or add the MCP server to Claude Code, Codex, Cursor or any client that speaks MCP. Both use the same analyzers as this page.</p>}>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div className="min-w-0"><h3 className="flex items-center gap-2 font-semibold"><Terminal size={16} className="text-ink" />CLI</h3><CodeBlock code={CLI} lang="bash" title="terminal" /></div>
          <div className="min-w-0"><h3 className="flex items-center gap-2 font-semibold"><Wand2 size={16} className="text-ink" />MCP server</h3><CodeBlock code={MCP} lang="json" title="mcp config" />
            <p className="text-sm text-muted">Your agent gets tools for analyze, sbom, secrets, strings, rules, diff and verify. Read the <Link to="/docs" className="text-ink underline underline-offset-4">docs</Link> for the full list.</p>
          </div>
        </div>
      </Section>
    </div>
  );
}
