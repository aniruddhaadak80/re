// Decoder loading. Both engines are WebAssembly. iced-x86 ships a Node build (it reads its .wasm
// with fs), so in a browser x86 falls back to Capstone, which loads in Node, browsers and workers.
import type { Arch, Decoder } from '../types.js';
import { IcedDecoder } from './iced.js';
import { CapstoneDecoder } from './capstone.js';

export interface DecoderOptions {
  /** prefer capstone for x86 even when iced-x86 loads (useful for cross checking) */
  preferCapstoneX86?: boolean;
  /** Capstone wasm bytes, for browsers where the .wasm file is not next to capstone.js */
  capstoneWasm?: Uint8Array | ArrayBuffer;
  /** emscripten locateFile hook for capstone.wasm */
  capstoneLocateFile?: (path: string, prefix: string) => string;
}

export interface DecoderSet {
  x86?: Decoder;
  arm?: Decoder;
  /** names of engines that failed to load, with the reason */
  errors: string[];
  get(arch: Arch): Decoder | undefined;
}

let icedP: Promise<IcedDecoder | Error> | undefined;
let csP: Promise<CapstoneDecoder | Error> | undefined;

function loadIced(): Promise<IcedDecoder | Error> {
  icedP ??= (async () => {
    try {
      const mod: { default?: unknown } = await import('iced-x86');
      const m = (mod.default ?? mod) as { Decoder?: unknown };
      if (!m.Decoder) return new Error('iced-x86 exports not found');
      return new IcedDecoder(m);
    } catch (e) {
      return e instanceof Error ? e : new Error(String(e));
    }
  })();
  return icedP;
}

function loadCapstone(opts: DecoderOptions): Promise<CapstoneDecoder | Error> {
  csP ??= (async () => {
    try {
      const mod: { default?: unknown } = await import('@alexaltea/capstone-js');
      const factory = (mod.default ?? mod) as (arg?: Record<string, unknown>) => Promise<unknown>;
      const arg: Record<string, unknown> = {};
      if (opts.capstoneWasm) arg.wasmBinary = opts.capstoneWasm;
      if (opts.capstoneLocateFile) arg.locateFile = opts.capstoneLocateFile;
      const cs = await factory(arg);
      return new CapstoneDecoder(cs);
    } catch (e) {
      csP = undefined;
      return e instanceof Error ? e : new Error(String(e));
    }
  })();
  return csP;
}

/** Load the decoding engines (cached after the first call). */
export async function loadDecoders(opts: DecoderOptions = {}): Promise<DecoderSet> {
  const [iced, cs] = await Promise.all([loadIced(), loadCapstone(opts)]);
  const errors: string[] = [];
  if (iced instanceof Error) errors.push('iced-x86: ' + iced.message);
  if (cs instanceof Error) errors.push('capstone: ' + cs.message);
  const csDec = cs instanceof Error ? undefined : cs;
  const icedDec = iced instanceof Error ? undefined : iced;
  const x86 = opts.preferCapstoneX86 ? csDec ?? icedDec : icedDec ?? csDec;
  return {
    x86, arm: csDec, errors,
    get(arch: Arch) { return arch === 'x86' || arch === 'x86_64' || arch === 'x86_16' ? x86 : arch === 'arm64' || arch === 'arm' || arch === 'ppc' ? csDec : undefined; },
  };
}
