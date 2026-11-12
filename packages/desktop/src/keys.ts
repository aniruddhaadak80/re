// Key combo parsing and per-platform key names (xdotool keysyms, macOS virtual key codes,
// Windows virtual-key codes, Linux evdev codes for ydotool). No Node imports.
import { InputError } from './proc.js';

export interface KeyCombo { mods: ('ctrl' | 'shift' | 'alt' | 'super')[]; key: string }

const MOD: Record<string, KeyCombo['mods'][number]> = { ctrl: 'ctrl', control: 'ctrl', ctl: 'ctrl', shift: 'shift', alt: 'alt', option: 'alt', opt: 'alt', meta: 'super', super: 'super', cmd: 'super', command: 'super', win: 'super', windows: 'super' };
const NAMED: Record<string, string> = {
  enter: 'enter', return: 'enter', tab: 'tab', esc: 'escape', escape: 'escape', space: 'space', backspace: 'backspace', delete: 'delete', del: 'delete',
  up: 'up', down: 'down', left: 'left', right: 'right', home: 'home', end: 'end', pageup: 'pageup', page_up: 'pageup', pgup: 'pageup', pagedown: 'pagedown', page_down: 'pagedown', pgdn: 'pagedown', insert: 'insert',
  uparrow: 'up', downarrow: 'down', leftarrow: 'left', rightarrow: 'right', arrowup: 'up', arrowdown: 'down', arrowleft: 'left', arrowright: 'right',
};

/** Parse "ctrl+shift+a", "Return", "cmd+Q" or "F5" into modifiers and one key. */
export function parseKeyCombo(s: string): KeyCombo {
  if (typeof s !== 'string' || !s.trim() || s.length > 100) throw new InputError('key must be a short string such as ctrl+a or Enter');
  const parts = s.split('+').map((p) => p.trim()).filter((p, i, a) => p || i === a.length - 1);
  const key = parts.pop() || '+';
  const mods: KeyCombo['mods'] = [];
  for (const p of parts) { const m = MOD[p.toLowerCase()]; if (!m) throw new InputError(`unknown modifier ${p}`); if (!mods.includes(m)) mods.push(m); }
  const lk = key.toLowerCase();
  if (NAMED[lk]) return { mods, key: NAMED[lk]! };
  if (/^f([1-9]|1[0-9]|2[0-4])$/.test(lk)) return { mods, key: lk };
  if ([...key].length === 1) return { mods, key: lk.length === 1 && /[a-z]/.test(lk) ? lk : key };
  if (/^[A-Za-z][A-Za-z0-9_]{1,30}$/.test(key)) return { mods, key }; // pass an X keysym such as KP_Enter through
  throw new InputError(`unknown key ${key}`);
}

const X11: Record<string, string> = { enter: 'Return', tab: 'Tab', escape: 'Escape', space: 'space', backspace: 'BackSpace', delete: 'Delete', up: 'Up', down: 'Down', left: 'Left', right: 'Right', home: 'Home', end: 'End', pageup: 'Prior', pagedown: 'Next', insert: 'Insert' };
const X11SYM: Record<string, string> = { '+': 'plus', '-': 'minus', '=': 'equal', ',': 'comma', '.': 'period', '/': 'slash', ';': 'semicolon', "'": 'apostrophe', '[': 'bracketleft', ']': 'bracketright', '\\': 'backslash', '`': 'grave', ' ': 'space' };

/** xdotool key argument, for example ctrl+shift+a or Return. */
export function toXdotool(c: KeyCombo): string {
  const k = X11[c.key] ?? (/^f\d+$/.test(c.key) ? c.key.toUpperCase() : X11SYM[c.key] ?? c.key);
  return [...c.mods, k].join('+');
}

/** macOS virtual key codes (kVK_*) for the ANSI layout. */
export const MAC_KEYCODE: Record<string, number> = {
  a: 0, s: 1, d: 2, f: 3, h: 4, g: 5, z: 6, x: 7, c: 8, v: 9, b: 11, q: 12, w: 13, e: 14, r: 15, y: 16, t: 17, '1': 18, '2': 19, '3': 20, '4': 21, '6': 22, '5': 23, '=': 24, '9': 25, '7': 26, '-': 27, '8': 28, '0': 29, ']': 30, o: 31, u: 32, '[': 33, i: 34, p: 35, l: 37, j: 38, "'": 39, k: 40, ';': 41, '\\': 42, ',': 43, '/': 44, n: 45, m: 46, '.': 47, '`': 50,
  enter: 36, tab: 48, space: 49, backspace: 51, escape: 53, delete: 117, home: 115, end: 119, pageup: 116, pagedown: 121, left: 123, right: 124, down: 125, up: 126,
  f1: 122, f2: 120, f3: 99, f4: 118, f5: 96, f6: 97, f7: 98, f8: 100, f9: 101, f10: 109, f11: 103, f12: 111,
};

/** Windows virtual-key codes. */
export function winVk(key: string): number {
  const named: Record<string, number> = { enter: 0x0d, tab: 0x09, escape: 0x1b, space: 0x20, backspace: 0x08, delete: 0x2e, up: 0x26, down: 0x28, left: 0x25, right: 0x27, home: 0x24, end: 0x23, pageup: 0x21, pagedown: 0x22, insert: 0x2d, ctrl: 0x11, shift: 0x10, alt: 0x12, super: 0x5b };
  if (named[key] !== undefined) return named[key]!;
  const f = /^f(\d+)$/.exec(key); if (f) return 0x6f + Number(f[1]);
  if (/^[a-z0-9]$/i.test(key)) return key.toUpperCase().charCodeAt(0);
  const oem: Record<string, number> = { ';': 0xba, '=': 0xbb, ',': 0xbc, '-': 0xbd, '.': 0xbe, '/': 0xbf, '`': 0xc0, '[': 0xdb, '\\': 0xdc, ']': 0xdd, "'": 0xde };
  if (oem[key] !== undefined) return oem[key]!;
  throw new InputError(`no Windows virtual key for ${key}`);
}

/** Linux evdev key codes (input-event-codes.h) for ydotool. */
export const EVDEV: Record<string, number> = {
  escape: 1, '1': 2, '2': 3, '3': 4, '4': 5, '5': 6, '6': 7, '7': 8, '8': 9, '9': 10, '0': 11, '-': 12, '=': 13, backspace: 14, tab: 15,
  q: 16, w: 17, e: 18, r: 19, t: 20, y: 21, u: 22, i: 23, o: 24, p: 25, '[': 26, ']': 27, enter: 28, ctrl: 29, a: 30, s: 31, d: 32, f: 33, g: 34, h: 35, j: 36, k: 37, l: 38, ';': 39, "'": 40, '`': 41, shift: 42, '\\': 43,
  z: 44, x: 45, c: 46, v: 47, b: 48, n: 49, m: 50, ',': 51, '.': 52, '/': 53, alt: 56, space: 57,
  f1: 59, f2: 60, f3: 61, f4: 62, f5: 63, f6: 64, f7: 65, f8: 66, f9: 67, f10: 68, f11: 87, f12: 88,
  home: 102, up: 103, pageup: 104, left: 105, right: 106, end: 107, down: 108, pagedown: 109, insert: 110, delete: 111, super: 125,
};

/** ydotool key arguments ("29:1 30:1 30:0 29:0") for a combo. */
export function toYdotool(c: KeyCombo): string[] {
  const codes = [...c.mods, c.key].map((k) => { const v = EVDEV[k.toLowerCase()]; if (v === undefined) throw new InputError(`no evdev code for ${k}`); return v; });
  return [...codes.map((v) => `${v}:1`), ...codes.reverse().map((v) => `${v}:0`)];
}
