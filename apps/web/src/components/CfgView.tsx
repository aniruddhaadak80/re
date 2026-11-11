import { useMemo } from 'react';

export interface CfgBlock { start: string; end: string; succ: { to: string; kind?: string }[]; insns: { addr: string; text: string; ref?: string }[] }

const W = 260, LINE = 14, PAD = 8, GAP_Y = 46, GAP_X = 36, MAX_LINES = 12;

/**
 * Control flow graph as SVG. Blocks are placed in layers by their shortest distance from the entry,
 * which keeps the layout stable and readable for the small to medium functions people open here.
 */
export function CfgView({ blocks, onBlock }: { blocks: CfgBlock[]; onBlock?: (addr: string) => void }) {
  const layout = useMemo(() => {
    const byStart = new Map(blocks.map((b) => [b.start, b]));
    const layer = new Map<string, number>();
    const first = blocks[0];
    if (first) {
      layer.set(first.start, 0);
      const q = [first.start];
      while (q.length) {
        const a = q.shift() as string;
        for (const s of byStart.get(a)?.succ ?? []) if (byStart.has(s.to) && !layer.has(s.to)) { layer.set(s.to, (layer.get(a) ?? 0) + 1); q.push(s.to); }
      }
    }
    let extra = Math.max(0, ...layer.values()) + 1;
    for (const b of blocks) if (!layer.has(b.start)) layer.set(b.start, extra++);
    const rows: string[][] = [];
    for (const b of blocks) { const l = layer.get(b.start) ?? 0; (rows[l] ??= []).push(b.start); }
    const height = (b: CfgBlock) => PAD * 2 + LINE * (Math.min(b.insns.length, MAX_LINES) + 1 + (b.insns.length > MAX_LINES ? 1 : 0));
    const pos = new Map<string, { x: number; y: number; h: number }>();
    const widest = Math.max(1, ...rows.map((r) => r?.length ?? 0));
    const totalW = widest * W + (widest - 1) * GAP_X;
    let y = 0;
    for (const r of rows) {
      if (!r) continue;
      const rowW = r.length * W + (r.length - 1) * GAP_X;
      let x = (totalW - rowW) / 2;
      let rowH = 0;
      for (const a of r) { const h = height(byStart.get(a) as CfgBlock); pos.set(a, { x, y, h }); rowH = Math.max(rowH, h); x += W + GAP_X; }
      y += rowH + GAP_Y;
    }
    return { pos, width: totalW, height: Math.max(0, y - GAP_Y), byStart };
  }, [blocks]);

  if (!blocks.length) return <p className="text-sm text-muted">No blocks.</p>;
  const color = (k?: string) => (k === 'true' ? '#14B8A6' : k === 'false' ? 'rgb(var(--accent))' : 'rgb(var(--muted))');
  return (
    <div className="max-h-[40rem] overflow-auto rounded-xl border border-line bg-surface2/40 p-3" data-testid="cfg-view">
      <svg width={layout.width + 8} height={layout.height + 8} viewBox={`-4 -4 ${layout.width + 8} ${layout.height + 8}`} role="img" aria-label={`Control flow graph with ${blocks.length} blocks`}>
        <defs>
          <marker id="cfg-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" /></marker>
        </defs>
        {blocks.flatMap((b) => b.succ.map((s, i) => {
          const a = layout.pos.get(b.start), t = layout.pos.get(s.to);
          if (!a || !t) return null;
          const x1 = a.x + W / 2 + (i - (b.succ.length - 1) / 2) * 24, y1 = a.y + a.h;
          const x2 = t.x + W / 2, y2 = t.y;
          const back = y2 <= y1;
          const d = back
            ? `M${x1},${y1} C${x1},${y1 + 30} ${Math.max(x1, x2) + W / 2 + 20},${y1 + 30} ${Math.max(x1, x2) + W / 2 + 20},${(y1 + y2) / 2} S${x2},${y2 - 30} ${x2},${y2}`
            : `M${x1},${y1} C${x1},${y1 + GAP_Y / 2} ${x2},${y2 - GAP_Y / 2} ${x2},${y2}`;
          return <path key={`${b.start}-${s.to}-${i}`} d={d} fill="none" stroke={color(s.kind)} strokeWidth={1.4} style={{ color: color(s.kind) }} markerEnd="url(#cfg-arrow)" strokeDasharray={back ? '4 3' : undefined} />;
        }))}
        {blocks.map((b) => {
          const p = layout.pos.get(b.start);
          if (!p) return null;
          return (
            <g key={b.start} transform={`translate(${p.x},${p.y})`} onClick={() => onBlock?.(b.start)} className="cursor-pointer" data-testid="cfg-block">
              <rect width={W} height={p.h} rx={8} fill="rgb(var(--surface))" stroke="rgb(var(--line))" />
              <text x={PAD} y={PAD + 10} fontSize={11} fontFamily="ui-monospace, monospace" fill="rgb(var(--ink))">{b.start}</text>
              {b.insns.slice(0, MAX_LINES).map((ins, i) => (
                <text key={ins.addr} x={PAD} y={PAD + 10 + LINE * (i + 1)} fontSize={10.5} fontFamily="ui-monospace, monospace" fill="rgb(var(--fg))">
                  {(ins.text + (ins.ref ? `  ; ${ins.ref}` : '')).slice(0, 38)}
                </text>
              ))}
              {b.insns.length > MAX_LINES && <text x={PAD} y={PAD + 10 + LINE * (MAX_LINES + 1)} fontSize={10} fill="rgb(var(--muted))">{b.insns.length - MAX_LINES} more</text>}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
