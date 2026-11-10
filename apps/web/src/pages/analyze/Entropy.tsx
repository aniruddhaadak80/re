import { useState } from 'react';
import { Activity } from 'lucide-react';
import { Empty } from '../../components/ui';
import { hex } from '../../lib/util';
import type { TabProps } from './shared';

const SECTION_COLORS = ['#F5B301', '#14B8A6', '#0EA5E9', '#F97316', '#10B981', '#FFD166', '#5EEAD4', '#FDBA74'];
const barColor = (v: number) => (v > 7.2 ? '#EF4444' : v > 6.5 ? '#F97316' : v > 5 ? '#F5B301' : v > 3 ? '#14B8A6' : '#0F766E');

export function Entropy({ report, jump }: TabProps) {
  const map = report.meta.entropyMap as { blockSize: number; values: number[] } | undefined;
  const [hover, setHover] = useState<number | null>(null);
  if (!map?.values.length) return <Empty title="No entropy map" icon={<Activity size={28} />}>The entropy analyzer did not run for this file.</Empty>;
  const { blockSize, values } = map;
  const W = 1000, H = 260, pad = 28, n = values.length, bw = (W - pad) / n;
  const size = report.file.size;
  const secs = report.sections.filter((s) => s.size > 0 && s.offset < size).slice(0, 40);
  const x = (off: number) => pad + (off / (n * blockSize)) * (W - pad);
  const secAt = (off: number) => secs.find((s) => off >= s.offset && off < s.offset + s.size);
  const hv = hover != null ? values[hover] : undefined;
  return (
    <div className="card p-4 sm:p-5" data-testid="entropy-chart">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-semibold">Entropy by block <span className="font-normal text-muted">({n} blocks of {blockSize.toLocaleString()} bytes)</span></p>
        <div className="flex flex-wrap gap-3 text-xs text-muted">
          <span className="flex items-center gap-1"><i className="h-2 w-3 rounded-sm bg-[#0F766E]" />plain</span>
          <span className="flex items-center gap-1"><i className="h-2 w-3 rounded-sm bg-[#F5B301]" />code</span>
          <span className="flex items-center gap-1"><i className="h-2 w-3 rounded-sm bg-[#EF4444]" />packed or encrypted</span>
        </div>
      </div>
      <div className="relative">
        <svg viewBox={`0 0 ${W} ${H + (secs.length ? 40 : 0)}`} className="h-auto w-full" onMouseLeave={() => setHover(null)} role="img" aria-label="Entropy chart">
          {[0, 2, 4, 6, 8].map((t) => (
            <g key={t}>
              <line x1={pad} x2={W} y1={H - (t / 8) * (H - 10)} y2={H - (t / 8) * (H - 10)} stroke="rgb(var(--line))" strokeDasharray="2 4" />
              <text x={0} y={H - (t / 8) * (H - 10) + 4} fontSize="11" fill="rgb(var(--muted))">{t}</text>
            </g>
          ))}
          {values.map((v, i) => {
            const h = (v / 8) * (H - 10);
            return (
              <rect key={i} x={pad + i * bw + 0.5} y={H - h} width={Math.max(1, bw - 1)} height={Math.max(1, h)} rx={Math.min(3, bw / 4)}
                fill={barColor(v)} opacity={hover == null || hover === i ? 1 : 0.55} className="cursor-pointer transition-opacity"
                onMouseEnter={() => setHover(i)} onClick={() => jump(i * blockSize, blockSize)} data-testid="entropy-bar" />
            );
          })}
          {secs.map((s, i) => {
            const x1 = x(s.offset), x2 = Math.max(x1 + 2, x(Math.min(size, s.offset + s.size)));
            return (
              <g key={`${s.name}-${i}`}>
                <rect x={x1} y={H + 8 + (i % 2) * 14} width={x2 - x1} height={10} rx={3} fill={SECTION_COLORS[i % SECTION_COLORS.length]} opacity={0.75}>
                  <title>{`${s.name} at ${hex(s.offset)}, ${s.size} bytes, entropy ${s.entropy.toFixed(2)}`}</title>
                </rect>
              </g>
            );
          })}
        </svg>
        {hover != null && hv != null && (
          <div className="pointer-events-none absolute top-2 z-10 rounded-lg border border-line bg-surface px-3 py-2 text-xs shadow-xl" style={{ left: `min(calc(${((hover + 0.5) / n) * 100}% ), calc(100% - 180px))` }} data-testid="entropy-tooltip">
            <p className="font-semibold">Block {hover + 1}</p>
            <p className="font-mono text-muted">{hex(hover * blockSize, 6)} to {hex(Math.min(size, (hover + 1) * blockSize), 6)}</p>
            <p>Entropy <span className="font-mono font-semibold">{hv.toFixed(3)}</span></p>
            {secAt(hover * blockSize) && <p className="text-muted">Section {secAt(hover * blockSize)!.name}</p>}
          </div>
        )}
      </div>
      {secs.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2 text-xs">
          {secs.slice(0, 16).map((s, i) => <span key={`${s.name}-${i}`} className="chip"><i className="h-2 w-2 rounded-full" style={{ background: SECTION_COLORS[i % SECTION_COLORS.length] }} />{s.name}</span>)}
        </div>
      )}
      <p className="mt-3 text-xs text-muted">Click a bar to open those bytes in the hex view. Text sits around 4 to 5 bits per byte, machine code near 6, and compressed or encrypted data close to 8.</p>
    </div>
  );
}
