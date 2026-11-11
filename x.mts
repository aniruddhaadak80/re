import { readFileSync } from 'node:fs';
const mods = [await import('./packages/managed/src/index.ts'), await import('./packages/webrt/src/index.ts'), await import('./packages/mobile/src/index.ts'), await import('./packages/disasm/src/index.ts')];
const TOOLS = new Map<string, any>(); for (const m of mods) for (const t of (m as any).TOOLS) TOOLS.set(t.name, t);
const map: Record<string, string> = { 'disasm/hello-x64.elf': 'disasm/hello-x64.elf', 'mobile/org.rayg.streaktracker_12.apk': 'mobile/apk/org.rayg.streaktracker_12.apk', 'mobile/hello-035.dex': 'mobile/java/hello-035.dex', 'mobile/Hello.class': 'mobile/java/Hello.class', 'mobile/Wikipedia-fixture.ipa': 'mobile/ipa/Wikipedia-fixture.ipa', 'managed/System.IO.Compression.Brotli.dll': 'managed/dotnet/System.IO.Compression.Brotli.dll', 'managed/sample_mod.3.12.pyc': 'managed/python/sample_mod.3.12.pyc', 'managed/sample.5.4.luac': 'managed/lua/sample.5.4.luac', 'managed/elixir_sup.beam': 'managed/beam/elixir_sup.beam', 'managed/RevToken.runtime.hex': 'managed/evm/RevToken.runtime.hex', 'webrt/obfuscated.js': 'webrt/obfuscated.js', 'webrt/bundle.prod.js': 'webrt/webpack-dist/bundle.prod.js', 'webrt/bundle.prod.js.map': 'webrt/webpack-dist/bundle.prod.js.map', 'webrt/app.asar': 'webrt/electron/app.asar', 'webrt/dns_udp.pcap': 'webrt/dns_udp.pcap', 'webrt/chrome-34-google.pcap': 'webrt/chrome-34-google.pcap', 'webrt/har-redirect.har': 'webrt/har-redirect.har', 'webrt/fixture.sqlite': 'webrt/fixture.sqlite' };
const { LABS } = await import('./apps/web/src/lib/labs.ts').catch(() => ({ LABS: [] as any[] }));
const runs: [string, string, any][] = [];
for (const lab of LABS) { for (const s of lab.samples) if (s.tool) runs.push([s.file, s.tool, {}]); for (const t of lab.tools) if (!t.auto) runs.push([lab.samples[0].file, t.tool, Object.fromEntries((t.fields ?? []).map((f: any) => [f.key, f.def ?? (f.placeholder ?? undefined)]).filter(([, v]: any) => v !== undefined).map(([k, v]: any) => [k, v === 'true' ? true : /^\d+$/.test(v) ? Number(v) : v]))]); }
for (const [file, tool, args] of runs) {
  const bytes = new Uint8Array(readFileSync('samples/' + map[file]));
  const input: any = { ...args, bytes };
  if (tool.startsWith('managed_')) { delete input.bytes; input.bytesBase64 = Buffer.from(bytes).toString('base64'); }
  try { const r = await TOOLS.get(tool).run(input); console.log('OK ', tool, file, JSON.stringify(r).length, JSON.stringify(r).slice(0, 160)); }
  catch (e) { console.log('ERR', tool, file, JSON.stringify(args), (e as Error).message); }
}
