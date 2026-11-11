import { readFileSync } from 'node:fs';
const mob: any = await import('./packages/mobile/src/index.ts');
const man: any = await import('./packages/managed/src/index.ts');
const web: any = await import('./packages/webrt/src/index.ts');
const T = (m: any, n: string) => m.TOOLS.find((t: any) => t.name === n);
for (const f of ['com.angrydoughnuts.android.alarmclock_27', 'de.markusfisch.android.screentime_16', 'omegacentauri.mobi.simplestopwatch_31']) {
  const bytes = new Uint8Array(readFileSync(`samples/mobile/apk/${f}.apk`));
  try { const r = await T(mob, 'mobile_dex_classes').run({ bytes, limit: 5 }); console.log(f, r.totalClasses, JSON.stringify(r.classes?.items?.slice(0, 3) ?? r).slice(0, 300)); } catch (e) { console.log(f, (e as Error).message); }
}
const dll = Buffer.from(readFileSync('samples/managed/dotnet/System.IO.Compression.Brotli.dll')).toString('base64');
const t = await T(man, 'managed_dotnet_types').run({ bytesBase64: dll, members: true, limit: 20 });
console.log(JSON.stringify(t.items.map((x: any) => [x.fullName, (x.methods ?? []).slice(0, 4).map((m: any) => m.name ?? m)])).slice(0, 1200));
const db = new Uint8Array(readFileSync('samples/webrt/fixture.sqlite'));
const s = await T(web, 'web_sqlite_tables').run({ bytes: db });
console.log(s.tables.map((x: any) => x.name));
