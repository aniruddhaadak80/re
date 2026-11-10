import { useRef, useState, type ReactNode } from 'react';
import { Lock, Upload } from 'lucide-react';
import { cx } from '../lib/util';

interface Props {
  onFiles: (files: File[]) => void;
  multiple?: boolean;
  compact?: boolean;
  title?: string;
  hint?: ReactNode;
  testId?: string;
  className?: string;
}

/** A local drop target. It marks the drop as handled so the page wide drop overlay ignores it. */
export function DropZone({ onFiles, multiple = true, compact = false, title = 'Drop files here or choose from your device', hint, testId = 'file-input', className }: Props) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => input.current?.click()}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.current?.click(); } }}
      onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); setOver(true); }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault(); e.stopPropagation();
        (e.nativeEvent as DragEvent & { revlensHandled?: boolean }).revlensHandled = true;
        setOver(false);
        const files = [...e.dataTransfer.files];
        if (files.length) onFiles(multiple ? files : files.slice(0, 1));
      }}
      className={cx(
        'group relative flex cursor-pointer flex-col items-center justify-center overflow-hidden rounded-2xl border-2 border-dashed text-center transition',
        over ? 'border-accent bg-accent/10' : 'border-line bg-surface hover:border-accent/60 hover:bg-surface2',
        compact ? 'gap-2 px-4 py-6' : 'gap-3 px-6 py-12',
        className,
      )}
    >
      <input
        ref={input}
        type="file"
        multiple={multiple}
        className="hidden"
        data-testid={testId}
        onChange={(e) => { const f = [...(e.target.files ?? [])]; if (f.length) onFiles(f); e.target.value = ''; }}
      />
      <div className={cx('grid place-items-center rounded-2xl border border-line bg-surface2 text-ink transition group-hover:scale-105 group-hover:border-accent/50', compact ? 'h-10 w-10' : 'h-14 w-14')}>
        <Upload size={compact ? 18 : 24} />
      </div>
      <p className={cx('font-medium', compact ? 'text-sm' : 'text-base')}>{title}</p>
      <p className="flex items-center gap-1.5 text-xs text-muted"><Lock size={12} className="text-teal" />Files never leave your device. Analysis runs in a local worker.</p>
      {hint && <div className="text-xs text-muted">{hint}</div>}
    </div>
  );
}
