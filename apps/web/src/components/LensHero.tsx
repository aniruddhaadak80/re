import { motion, useMotionValue, useSpring, useTransform } from 'framer-motion';
import { useReducedMotionSetting } from '../lib/settings';

const FORMATS = ['ELF', 'PE', 'Mach-O', 'WASM', 'APK', 'CRX', 'VSIX', 'npm'];
const FINDINGS = ['react-dom 18.3.1', 'T1059 shell', 'AWS key', 'UPX packed', 'SBOM 42 deps', 'eval(atob)', 'imphash', '.text 6.2 bits'];
const R_OUT = 232;
const DUR = 4.8;

const rad = (deg: number) => (deg * Math.PI) / 180;
const at = (deg: number, r: number) => ({ x: Math.cos(rad(deg)) * r, y: Math.sin(rad(deg)) * r });

function Chip({ label, tone }: { label: string; tone: 'gold' | 'teal' }) {
  const w = Math.max(44, label.length * 7.4 + 22);
  return (
    <g>
      <rect x={-w / 2} y={-14} width={w} height={28} rx={14}
        fill={tone === 'gold' ? 'rgb(var(--surface))' : 'rgba(20,184,166,0.14)'}
        stroke={tone === 'gold' ? 'rgb(var(--accent))' : '#14B8A6'} strokeOpacity={0.85} strokeWidth={1.2} />
      <text x={0} y={4.5} textAnchor="middle" fontSize={12.5} fontFamily="JetBrains Mono, ui-monospace, monospace" fontWeight={600}
        fill={tone === 'gold' ? 'rgb(var(--ink))' : '#2DD4BF'}>{label}</text>
    </g>
  );
}

/** The animated lens: format chips orbit in, pass through the lens, and leave as findings. */
export function LensHero() {
  const reduced = useReducedMotionSetting();
  const mx = useMotionValue(0), my = useMotionValue(0);
  const rx = useSpring(useTransform(my, [-0.5, 0.5], [9, -9]), { stiffness: 120, damping: 16 });
  const ry = useSpring(useTransform(mx, [-0.5, 0.5], [-11, 11]), { stiffness: 120, damping: 16 });

  return (
    <div
      className="relative mx-auto aspect-square w-full max-w-[520px] select-none"
      style={{ perspective: 1000 }}
      onMouseMove={(e) => {
        if (reduced) return;
        const r = e.currentTarget.getBoundingClientRect();
        mx.set((e.clientX - r.left) / r.width - 0.5); my.set((e.clientY - r.top) / r.height - 0.5);
      }}
      onMouseLeave={() => { mx.set(0); my.set(0); }}
      data-testid="lens-hero"
      aria-hidden
    >
      <motion.div className="h-full w-full" style={reduced ? undefined : { rotateX: rx, rotateY: ry, transformStyle: 'preserve-3d' }}>
        <svg viewBox="-260 -260 520 520" className="h-full w-full overflow-hidden" role="img">
          <defs>
            <radialGradient id="lens-glass" cx="0.4" cy="0.35" r="0.75">
              <stop offset="0" stopColor="rgb(var(--accent2))" stopOpacity="0.55" />
              <stop offset="0.45" stopColor="rgb(var(--accent))" stopOpacity="0.16" />
              <stop offset="1" stopColor="rgb(var(--bg))" stopOpacity="0" />
            </radialGradient>
            <radialGradient id="lens-halo" cx="0.5" cy="0.5" r="0.5">
              <stop offset="0.55" stopColor="rgb(var(--accent))" stopOpacity="0.18" />
              <stop offset="1" stopColor="rgb(var(--accent))" stopOpacity="0" />
            </radialGradient>
            <linearGradient id="lens-ring" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stopColor="rgb(var(--accent2))" />
              <stop offset="0.6" stopColor="rgb(var(--accent))" />
              <stop offset="1" stopColor="#14B8A6" />
            </linearGradient>
          </defs>

          <circle r={250} fill="url(#lens-halo)" />
          <motion.g animate={reduced ? undefined : { rotate: 360 }} transition={{ duration: 60, ease: 'linear', repeat: Infinity }}>
            <circle r={210} fill="none" stroke="rgb(var(--accent))" strokeOpacity={0.25} strokeWidth={1.2} strokeDasharray="3 9" />
            {Array.from({ length: 48 }, (_, i) => {
              const a = at(i * 7.5, 210), b = at(i * 7.5, i % 4 === 0 ? 198 : 204);
              return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="rgb(var(--accent))" strokeOpacity={i % 4 === 0 ? 0.5 : 0.2} strokeWidth={1.2} />;
            })}
          </motion.g>
          <motion.g animate={reduced ? undefined : { rotate: -360 }} transition={{ duration: 38, ease: 'linear', repeat: Infinity }}>
            <circle r={168} fill="none" stroke="#14B8A6" strokeOpacity={0.45} strokeWidth={1.4} strokeDasharray="1 7" strokeLinecap="round" />
            <circle cx={168} cy={0} r={5} fill="#14B8A6" />
            <circle cx={-168} cy={0} r={3} fill="#14B8A6" fillOpacity={0.6} />
          </motion.g>
          <circle r={124} fill="url(#lens-glass)" />
          <motion.g animate={reduced ? undefined : { rotate: 360 }} transition={{ duration: 24, ease: 'linear', repeat: Infinity }}>
            <circle r={124} fill="none" stroke="url(#lens-ring)" strokeWidth={9} />
            <circle r={124} fill="none" stroke="rgb(var(--bg))" strokeOpacity={0.6} strokeWidth={9} strokeDasharray="2 46" />
          </motion.g>
          <motion.g animate={reduced ? undefined : { rotate: -360 }} transition={{ duration: 16, ease: 'linear', repeat: Infinity }}>
            <circle r={72} fill="none" stroke="rgb(var(--accent2))" strokeOpacity={0.8} strokeWidth={1.6} strokeDasharray="10 8" />
          </motion.g>
          <motion.circle r={26} fill="#14B8A6" animate={reduced ? undefined : { r: [24, 30, 24], opacity: [0.85, 1, 0.85] }} transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }} />
          <circle r={10} fill="rgb(var(--bg))" fillOpacity={0.55} />
          <path d="M -60 -88 A 108 108 0 0 1 40 -100" fill="none" stroke="white" strokeOpacity={0.35} strokeWidth={4} strokeLinecap="round" />

          {FORMATS.map((f, i) => {
            const deg = -150 + i * 38;
            const start = at(deg, R_OUT), near = at(deg + 6, 212), mid = at(deg + 18, 150);
            if (reduced) { const p = at(deg, 200); return <g key={f} transform={`translate(${p.x} ${p.y})`}><Chip label={f} tone="gold" /></g>; }
            return (
              <motion.g key={f} initial={{ opacity: 0 }}
                animate={{ x: [start.x, near.x, mid.x, 0], y: [start.y, near.y, mid.y, 0], opacity: [0, 1, 1, 0], scale: [0.9, 1, 1, 0.35] }}
                transition={{ duration: DUR, times: [0, 0.12, 0.6, 1], delay: i * (DUR / FORMATS.length), repeat: Infinity, ease: 'easeIn' }}>
                <Chip label={f} tone="gold" />
              </motion.g>
            );
          })}
          {FINDINGS.map((f, i) => {
            const deg = 15 + i * 41;
            const end = at(deg, 205), mid = at(deg - 14, 120), first = at(deg - 20, 60);
            if (reduced) return null;
            return (
              <motion.g key={f} initial={{ opacity: 0 }}
                animate={{ x: [first.x, mid.x, end.x, end.x], y: [first.y, mid.y, end.y, end.y], opacity: [0, 1, 1, 0], scale: [0.35, 1, 1, 1] }}
                transition={{ duration: DUR, times: [0, 0.3, 0.8, 1], delay: DUR * 0.55 + i * (DUR / FINDINGS.length), repeat: Infinity, ease: 'easeOut' }}>
                <Chip label={f} tone="teal" />
              </motion.g>
            );
          })}
        </svg>
      </motion.div>
    </div>
  );
}
