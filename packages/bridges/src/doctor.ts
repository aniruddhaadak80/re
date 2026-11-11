// Capability inventory: which external tools are installed, what they unlock, and how to install
// the missing ones on this OS. Node only (it runs version probes).
import { arch } from 'node:os';
import { currentPlatform, installFor, TOOL_IDS, TOOL_META } from './catalog.js';
import { detectAll, type DetectOptions } from './detect.js';
import type { Inventory, InventoryEntry, Platform, ToolId } from './types.js';

/** Build the capability inventory for this machine. */
export async function inventory(opts: DetectOptions & { platform?: NodeJS.Platform } = {}): Promise<Inventory> {
  const dets = await detectAll(opts);
  const platform: Platform = currentPlatform(opts.platform ?? process.platform);
  const tools: InventoryEntry[] = [];
  const capabilities: Record<string, ToolId[]> = {};
  for (const id of TOOL_IDS) {
    const meta = TOOL_META[id];
    const det = dets.get(id) ?? { id, name: meta.name, available: false };
    const broken = det.available && (det.problems?.length ?? 0) > 0;
    const entry: InventoryEntry = {
      ...det,
      description: meta.description,
      capabilities: meta.capabilities,
      requires: meta.requires,
      ...(!det.available || broken ? { install: installFor(id, platform) } : {}),
    };
    tools.push(entry);
    if (det.available) for (const c of meta.capabilities) (capabilities[c] ??= []).push(id);
  }
  const available = tools.filter((t) => t.available).length;
  return {
    schema: 'revlens/bridges-inventory@1', platform, arch: arch(), generatedAt: new Date().toISOString(),
    tools, capabilities, summary: { available, missing: tools.length - available, total: tools.length },
  };
}

/** Best single install command line for a tool on a platform, for short human output. */
export function primaryInstall(e: InventoryEntry): string | undefined {
  const i = e.install;
  if (!i) return undefined;
  return i.brew ?? i.apt ?? i.winget ?? i.scoop ?? i.choco ?? i.pip ?? i.dotnet ?? i.cargo ?? i.script ?? (i.url ? `download: ${i.url}` : i.note);
}

/** Plain text report for `revlens doctor`. */
export function formatInventory(inv: Inventory, opts: { verbose?: boolean } = {}): string {
  const out: string[] = [];
  out.push(`RevLens bridges doctor (${inv.platform} ${inv.arch})`);
  out.push(`${inv.summary.available} of ${inv.summary.total} tools found.`);
  out.push('');
  const w = Math.max(...inv.tools.map((t) => t.name.length));
  for (const t of inv.tools) {
    const mark = t.available ? (t.problems?.length ? 'partial' : 'ok') : 'missing';
    const ver = t.version ? ` ${t.version}` : '';
    out.push(`  ${t.name.padEnd(w)}  ${mark.padEnd(7)}${ver}${t.available && t.path ? `  ${t.path}` : ''}`);
    for (const p of t.problems ?? []) out.push(`  ${' '.repeat(w)}  note: ${p}`);
    if (t.id === 'radare2' || t.id === 'rizin') {
      if (t.available && t.details?.ghidraPlugin === false) out.push(`  ${' '.repeat(w)}  note: no decompiler plugin, install r2ghidra (r2pm -ci r2ghidra) or rz-ghidra for C output`);
    }
    if (!t.available || t.problems?.length) {
      const cmd = primaryInstall(t);
      if (cmd) out.push(`  ${' '.repeat(w)}  install: ${cmd}`);
      if (opts.verbose && t.install) {
        for (const [k, v] of Object.entries(t.install)) if (k !== 'homepage' && v && v !== cmd) out.push(`  ${' '.repeat(w)}    ${k}: ${v}`);
        out.push(`  ${' '.repeat(w)}    homepage: ${t.install.homepage}`);
      }
    }
  }
  out.push('');
  const caps = Object.keys(inv.capabilities).sort();
  out.push(`Capabilities ready: ${caps.length ? caps.join(', ') : 'none'}`);
  out.push('Environment overrides: REVLENS_<TOOL>_PATH (for example REVLENS_RADARE2_PATH), GHIDRA_INSTALL_DIR, JADX_HOME, IDADIR, BN_INSTALL_DIR, JAVA_HOME.');
  return out.join('\n');
}
