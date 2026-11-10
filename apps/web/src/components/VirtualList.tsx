import { useEffect, useRef, useState, type ReactNode } from 'react';

interface Props<T> { items: T[]; rowHeight: number; height: number; render: (item: T, index: number) => ReactNode; scrollToIndex?: number; className?: string; testId?: string }

/** Fixed row height virtual list. Renders only the rows in view plus a small overscan. */
export function VirtualList<T>({ items, rowHeight, height, render, scrollToIndex, className = '', testId }: Props<T>) {
  const ref = useRef<HTMLDivElement>(null);
  const [top, setTop] = useState(0);
  useEffect(() => {
    if (scrollToIndex == null || !ref.current) return;
    const y = Math.max(0, scrollToIndex * rowHeight - height / 3);
    ref.current.scrollTop = y; setTop(y);
  }, [scrollToIndex, rowHeight, height]);
  const start = Math.max(0, Math.floor(top / rowHeight) - 8);
  const end = Math.min(items.length, Math.ceil((top + height) / rowHeight) + 8);
  const rows: ReactNode[] = [];
  for (let i = start; i < end; i++) rows.push(<div key={i} style={{ position: 'absolute', top: i * rowHeight, height: rowHeight, left: 0, right: 0 }}>{render(items[i] as T, i)}</div>);
  return (
    <div ref={ref} className={`relative overflow-auto ${className}`} style={{ height }} onScroll={(e) => setTop(e.currentTarget.scrollTop)} data-testid={testId}>
      <div style={{ height: items.length * rowHeight, position: 'relative', minWidth: '100%' }}>{rows}</div>
    </div>
  );
}
