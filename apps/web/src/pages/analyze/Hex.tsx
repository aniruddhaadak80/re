import { useMemo, useState } from 'react';
import { VirtualList } from '../../components/VirtualList';
import { cx, hex } from '../../lib/util';
import type { TabProps } from './shared';

const W = 16;
const H2 = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0').toUpperCase());

export function Hex({ file, target }: TabProps & { target: { offset: number; length: number; nonce: number } | null }) {
  const bytes = file.bytes;
  const rows = Math.ceil(bytes.length / W);
  const [goto, setGoto] = useState('');
  const [local, setLocal] = useState<{ offset: number; length: number; nonce: number } | null>(null);
  const sel = local && (!target || local.nonce > target.nonce) ? local : target;
  const lo = sel?.offset ?? -1, hi = sel ? sel.offset + Math.max(1, sel.length) : -1;
  const items = useMemo(() => Array.from({ length: rows }, (_, i) => i), [rows]);
  return (
    <div className="card overflow-hidden" data-testid="hex-view">
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
        <p className="text-sm font-semibold">Hex <span className="font-normal text-muted">{bytes.length.toLocaleString()} bytes</span></p>
        <form className="ml-auto flex gap-2" onSubmit={(e) => { e.preventDefault(); const n = Number(goto.trim().startsWith('0x') ? parseInt(goto, 16) : goto); if (Number.isFinite(n) && n >= 0 && n < bytes.length) setLocal({ offset: n, length: 1, nonce: Date.now() }); }}>
          <input className="input !w-40 font-mono" value={goto} onChange={(e) => setGoto(e.target.value)} placeholder="Offset, 0x10 or 16" aria-label="Go to offset" />
          <button className="btn-ghost btn-sm" type="submit">Go</button>
        </form>
        {sel && <span className="w-full font-mono text-xs text-ink sm:w-auto" data-testid="hex-selection">Selected {hex(sel.offset, 6)}, {sel.length} bytes</span>}
      </div>
      <div className="overflow-x-auto">
        <div className="min-w-[700px]">
          <VirtualList items={items} rowHeight={22} height={520} scrollToIndex={sel ? Math.floor(sel.offset / W) : undefined}
            render={(r) => {
              const start = r * W;
              const cells: JSX.Element[] = [], chars: JSX.Element[] = [];
              for (let i = 0; i < W; i++) {
                const o = start + i;
                if (o >= bytes.length) break;
                const b = bytes[o] as number;
                const on = o >= lo && o < hi;
                cells.push(<span key={i} className={cx('inline-block w-[22px] text-center', on ? 'rounded-sm bg-accent text-night' : b === 0 ? 'text-muted/50' : '', i === 7 && 'mr-2')}>{H2[b]}</span>);
                chars.push(<span key={i} className={cx(on && 'bg-accent text-night', b < 32 || b > 126 ? 'text-muted/50' : '')}>{b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'}</span>);
              }
              return (
                <div className={cx('flex h-full items-center gap-4 px-3 font-mono text-[12px]', start <= lo && lo < start + W && 'bg-accent/5')}>
                  <span className="w-20 shrink-0 text-ink/80">{start.toString(16).toUpperCase().padStart(8, '0')}</span>
                  <span className="shrink-0">{cells}</span>
                  <span className="whitespace-pre">{chars}</span>
                </div>
              );
            }} />
        </div>
      </div>
    </div>
  );
}
