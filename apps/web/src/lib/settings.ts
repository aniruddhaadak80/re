import { useSyncExternalStore } from 'react';

export type Theme = 'black' | 'dark' | 'sun' | 'system';
export type Accent = 'gold' | 'teal' | 'amber' | 'emerald' | 'sky' | 'orange';
export type Motion = 'full' | 'reduced' | 'system';
export interface Settings { theme: Theme; accent: Accent; motion: Motion }

export const THEMES: { id: Theme; label: string }[] = [
  { id: 'black', label: 'Black' }, { id: 'dark', label: 'Dark' }, { id: 'sun', label: 'Sun' }, { id: 'system', label: 'System' },
];
export const ACCENTS: { id: Accent; label: string; hex: string }[] = [
  { id: 'gold', label: 'Gold', hex: '#F5B301' }, { id: 'teal', label: 'Teal', hex: '#14B8A6' },
  { id: 'amber', label: 'Amber', hex: '#F59E0B' }, { id: 'emerald', label: 'Emerald', hex: '#10B981' },
  { id: 'sky', label: 'Sky', hex: '#0EA5E9' }, { id: 'orange', label: 'Orange', hex: '#F97316' },
];

const KEY = 'revlens.settings';
const DEFAULTS: Settings = { theme: 'black', accent: 'gold', motion: 'system' };

function read(): Settings {
  try { return { ...DEFAULTS, ...(JSON.parse(localStorage.getItem(KEY) ?? '{}') as Partial<Settings>) }; } catch { return DEFAULTS; }
}

let current: Settings = typeof window === 'undefined' ? DEFAULTS : read();
const listeners = new Set<() => void>();

export function resolvedTheme(t: Theme): Exclude<Theme, 'system'> {
  if (t !== 'system') return t;
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'sun' : 'black';
}

export function applySettings(s: Settings = current): void {
  const d = document.documentElement;
  const t = resolvedTheme(s.theme);
  d.dataset.theme = t;
  d.dataset.accent = s.accent;
  d.classList.toggle('dark', t !== 'sun');
  if (s.motion === 'reduced') d.dataset.motion = 'reduced'; else delete d.dataset.motion;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', t === 'sun' ? '#FAF9F5' : t === 'dark' ? '#16171A' : '#0A0A0B');
}

export function setSettings(patch: Partial<Settings>): void {
  current = { ...current, ...patch };
  try { localStorage.setItem(KEY, JSON.stringify(current)); } catch { /* private mode */ }
  applySettings(current);
  listeners.forEach((l) => l());
}

export function useSettings(): Settings {
  return useSyncExternalStore((cb) => { listeners.add(cb); return () => listeners.delete(cb); }, () => current, () => current);
}

export function initSettings(): void {
  applySettings(current);
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => { if (current.theme === 'system') applySettings(current); listeners.forEach((l) => l()); });
}

/** True when animations should be reduced, from the user setting or the OS. */
export function useReducedMotionSetting(): boolean {
  const s = useSettings();
  const os = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  return s.motion === 'reduced' || (s.motion === 'system' && os);
}
