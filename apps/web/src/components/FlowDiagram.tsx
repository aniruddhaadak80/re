import { motion } from 'framer-motion';
import { Bot, Cpu, FileInput, FileJson, ScanSearch, ShieldCheck } from 'lucide-react';
import { Fragment } from 'react';
import { useReducedMotionSetting } from '../lib/settings';

const STEPS = [
  { icon: FileInput, title: 'Your file', text: 'Binary, bundle, archive or extension. Read as bytes, never uploaded.' },
  { icon: ScanSearch, title: 'Detect', text: 'Magic bytes pick the format: ELF, PE, Mach-O, WASM, ZIP family, JS and more.' },
  { icon: Cpu, title: 'Analyzers', text: 'Each analyzer runs in a worker and adds sections, strings, components and findings.' },
  { icon: ShieldCheck, title: 'Rules and checks', text: 'yara-lite rules, secrets, capabilities mapped to ATT&CK, optional OSV lookup.' },
  { icon: FileJson, title: 'Report', text: 'One JSON report with evidence offsets. Export SARIF, CycloneDX, Markdown or HTML.' },
  { icon: Bot, title: 'Your agent', text: 'The same core runs in the CLI and the MCP server, so agents get the same answers.' },
];

function Connector({ vertical, reduced, i }: { vertical: boolean; reduced: boolean; i: number }) {
  return vertical ? (
    <svg width="24" height="36" viewBox="0 0 24 36" className="mx-auto xl:hidden" aria-hidden>
      <line x1="12" y1="0" x2="12" y2="36" stroke="rgb(var(--line))" strokeWidth="2" />
      <line x1="12" y1="0" x2="12" y2="36" stroke="#14B8A6" strokeWidth="2" strokeDasharray="4 6" className={reduced ? '' : 'animate-dash'} />
      {!reduced && <motion.circle cx="12" r="3" fill="rgb(var(--accent))" animate={{ cy: [0, 36] }} transition={{ duration: 1.4, repeat: Infinity, delay: i * 0.25, ease: 'easeInOut' }} />}
    </svg>
  ) : (
    <svg viewBox="0 0 48 24" className="hidden h-6 w-full min-w-[24px] self-center xl:block" preserveAspectRatio="none" aria-hidden>
      <line x1="0" y1="12" x2="48" y2="12" stroke="rgb(var(--line))" strokeWidth="2" />
      <line x1="0" y1="12" x2="48" y2="12" stroke="#14B8A6" strokeWidth="2" strokeDasharray="4 6" className={reduced ? '' : 'animate-dash'} />
      {!reduced && <motion.circle cy="12" r="3" fill="rgb(var(--accent))" animate={{ cx: [0, 48] }} transition={{ duration: 1.4, repeat: Infinity, delay: i * 0.25, ease: 'easeInOut' }} />}
    </svg>
  );
}

/** How it works, drawn with SVG connectors and small framer motion pulses. No external diagram service. */
export function FlowDiagram() {
  const reduced = useReducedMotionSetting();
  return (
    <div className="grid grid-cols-1 xl:grid-cols-[repeat(11,auto)] xl:items-stretch" data-testid="flow-diagram">
      {STEPS.map((s, i) => (
        <Fragment key={s.title}>
          <motion.div
            className="card card-hover relative p-4 xl:w-[168px]"
            initial={reduced ? false : { opacity: 0, y: 16 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, margin: '-40px' }}
            transition={{ delay: i * 0.08, duration: 0.4 }}
          >
            <div className="mb-3 grid grid-cols-1 h-9 w-9 place-items-center rounded-xl border border-accent/40 bg-accent/10 text-ink"><s.icon size={18} /></div>
            <p className="text-sm font-semibold">{s.title}</p>
            <p className="mt-1 text-xs leading-5 text-muted">{s.text}</p>
          </motion.div>
          {i < STEPS.length - 1 && <><Connector vertical reduced={reduced} i={i} /><Connector vertical={false} reduced={reduced} i={i} /></>}
        </Fragment>
      ))}
    </div>
  );
}
