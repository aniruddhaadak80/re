// Copies sample files and markdown assets into public/, and makes the OG image and PWA icons.
// Runs before dev and build. Everything it writes under public/samples and public/content is generated.
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const web = join(here, '..');
const repo = join(web, '..', '..');
const pub = join(web, 'public');

const SAMPLES = ['ls-linux.elf', 'react-dom.production.min.js', 'jquery.min.js', 'jquery.min.map', 'left-pad-1.3.0.tgz'];
mkdirSync(join(pub, 'samples'), { recursive: true });
for (const s of SAMPLES) {
  const src = join(repo, 'samples', s);
  if (existsSync(src)) cpSync(src, join(pub, 'samples', s));
  else console.warn(`[prebuild] sample missing: ${s}`);
}

// Small real fixtures for the tool pages, copied from the packages' sample folders.
const LAB_SAMPLES = {
  'disasm/hello-x64.elf': 'disasm/hello-x64.elf', 'disasm/hello-arm64.elf': 'disasm/hello-arm64.elf', 'disasm/hello-x64.exe': 'disasm/hello-x64.exe',
  'mobile/com.angrydoughnuts.android.alarmclock_27.apk': 'mobile/apk/com.angrydoughnuts.android.alarmclock_27.apk', 'mobile/hello-035.dex': 'mobile/java/hello-035.dex',
  'mobile/Hello.class': 'mobile/java/Hello.class', 'mobile/Wikipedia-fixture.ipa': 'mobile/ipa/Wikipedia-fixture.ipa',
  'managed/System.IO.Compression.Brotli.dll': 'managed/dotnet/System.IO.Compression.Brotli.dll', 'managed/sample_mod.3.12.pyc': 'managed/python/sample_mod.3.12.pyc',
  'managed/sample.5.4.luac': 'managed/lua/sample.5.4.luac', 'managed/elixir_sup.beam': 'managed/beam/elixir_sup.beam', 'managed/RevToken.runtime.hex': 'managed/evm/RevToken.runtime.hex',
  'webrt/obfuscated.js': 'webrt/obfuscated.js', 'webrt/bundle.prod.js': 'webrt/webpack-dist/bundle.prod.js', 'webrt/bundle.prod.js.map': 'webrt/webpack-dist/bundle.prod.js.map',
  'webrt/app.asar': 'webrt/electron/app.asar', 'webrt/dns_udp.pcap': 'webrt/dns_udp.pcap', 'webrt/chrome-34-google.pcap': 'webrt/chrome-34-google.pcap',
  'webrt/har-redirect.har': 'webrt/har-redirect.har', 'webrt/fixture.sqlite': 'webrt/fixture.sqlite',
};
for (const [to, from] of Object.entries(LAB_SAMPLES)) {
  const src = join(repo, 'samples', from);
  if (!existsSync(src)) { console.warn(`[prebuild] lab sample missing: ${from}`); continue; }
  mkdirSync(dirname(join(pub, 'samples', to)), { recursive: true });
  cpSync(src, join(pub, 'samples', to));
}

// Non-markdown assets next to docs and blog posts (images, diagrams).
const copyAssets = (from, to) => {
  if (!existsSync(from)) return;
  rmSync(to, { recursive: true, force: true });
  const walk = (dir, rel = '') => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p, join(rel, name));
      else if (!name.endsWith('.md')) { mkdirSync(join(to, rel), { recursive: true }); cpSync(p, join(to, rel, name)); }
    }
  };
  walk(from);
};
copyAssets(join(repo, 'docs'), join(pub, 'content', 'docs'));
copyAssets(join(repo, 'content', 'blog'), join(pub, 'content', 'blog'));

// OG image and icons. Generated once, then kept in public/ so CI does not need sharp.
const lens = (size) => `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="14" fill="#0A0A0B"/>
  <circle cx="32" cy="32" r="20" fill="none" stroke="#F5B301" stroke-width="4"/>
  <circle cx="32" cy="32" r="11" fill="none" stroke="#FFD166" stroke-width="2" stroke-dasharray="4 3"/>
  <circle cx="32" cy="32" r="4" fill="#14B8A6"/>
  <path d="M46 46 L56 56" stroke="#F5B301" stroke-width="5" stroke-linecap="round"/>
</svg>`;
const og = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <radialGradient id="g" cx="0.78" cy="0.45" r="0.6"><stop offset="0" stop-color="#F5B301" stop-opacity="0.35"/><stop offset="1" stop-color="#0A0A0B" stop-opacity="0"/></radialGradient>
  </defs>
  <rect width="1200" height="630" fill="#0A0A0B"/>
  <rect width="1200" height="630" fill="url(#g)"/>
  <g transform="translate(1030 300) scale(0.8)" fill="none">
    <circle r="200" stroke="#F5B301" stroke-opacity="0.18" stroke-width="2" stroke-dasharray="6 10"/>
    <circle r="150" stroke="#14B8A6" stroke-opacity="0.45" stroke-width="2"/>
    <circle r="100" stroke="#F5B301" stroke-width="10"/>
    <circle r="55" stroke="#FFD166" stroke-width="3" stroke-dasharray="10 8"/>
    <circle r="18" fill="#14B8A6"/>
  </g>
  <g font-family="DejaVu Sans, Arial, sans-serif">
    <text x="80" y="210" font-size="88" font-weight="700" fill="#F5B301">RevLens</text>
    <text x="80" y="290" font-size="34" fill="#F2EFE6">Look inside any binary, bundle or package.</text>
    <text x="80" y="342" font-size="34" fill="#F2EFE6">In your browser, your terminal, or your agent.</text>
    <text x="80" y="450" font-size="26" fill="#14B8A6">ELF  PE  Mach-O  WASM  APK  CRX  VSIX  npm</text>
    <text x="80" y="540" font-size="24" fill="#A39F94">aniruddhaadak80.github.io/re</text>
  </g>
</svg>`;
writeFileSync(join(pub, 'favicon.svg'), lens(64));
writeFileSync(join(pub, 'og.svg'), og);
const need = ['og.png', 'icons/icon-192.png', 'icons/icon-512.png', 'icons/apple-touch-icon.png'].filter((f) => !existsSync(join(pub, f)));
if (need.length) {
  try {
    const sharp = (await import('sharp')).default;
    mkdirSync(join(pub, 'icons'), { recursive: true });
    await sharp(Buffer.from(og)).png().toFile(join(pub, 'og.png'));
    await sharp(Buffer.from(lens(512))).resize(192, 192).png().toFile(join(pub, 'icons/icon-192.png'));
    await sharp(Buffer.from(lens(512))).png().toFile(join(pub, 'icons/icon-512.png'));
    await sharp(Buffer.from(lens(512))).resize(180, 180).png().toFile(join(pub, 'icons/apple-touch-icon.png'));
    console.log('[prebuild] generated og.png and icons');
  } catch (e) {
    console.warn('[prebuild] sharp not available, using SVG only:', e.message);
  }
}
console.log('[prebuild] done');
