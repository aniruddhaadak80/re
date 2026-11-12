// Downloads three real OpenWrt 23.05.5 router images (GPL-2.0, not committed) into
// samples/.cache/extras/openwrt and checks them against the SHA-256 values OpenWrt publishes.
// Run: node packages/extras/scripts/fetch-openwrt.mjs   (the OpenWrt tests skip when absent)
import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const cache = join(here, '..', '..', '..', 'samples', '.cache', 'extras', 'openwrt');
mkdirSync(cache, { recursive: true });
const BASE = 'https://downloads.openwrt.org/releases/23.05.5/targets';
export const OPENWRT_IMAGES = [
  { file: 'openwrt-23.05.5-bcm47xx-generic-standard-squashfs.trx', target: 'bcm47xx/generic', sha256: '081fa544291e80e735a24b0b28ae6ee4ccdc896b25e8e7ba30b4532e186a700c' },
  { file: 'openwrt-23.05.5-ramips-mt7621-xiaomi_mi-router-4a-gigabit-squashfs-sysupgrade.bin', target: 'ramips/mt7621', sha256: 'c7c0146c21e5bee27e13db604cf025e7de9fae96fae9ff2fa49c3e435bfe28ae' },
  { file: 'openwrt-23.05.5-ath79-generic-tplink_archer-c7-v2-squashfs-sysupgrade.bin', target: 'ath79/generic', sha256: '4e22524a1a59090d8f316ad48b13a61ab46f748d9b6215ec0926f9747369fcd5' },
];
const sha = (b) => createHash('sha256').update(b).digest('hex');
for (const img of OPENWRT_IMAGES) {
  const out = join(cache, img.file);
  if (existsSync(out) && sha(readFileSync(out)) === img.sha256) { console.log('ok (cached)', img.file); continue; }
  const r = await fetch(`${BASE}/${img.target}/${img.file}`, { redirect: 'follow' });
  if (!r.ok) throw new Error(`${img.file}: HTTP ${r.status}`);
  const b = new Uint8Array(await r.arrayBuffer());
  if (sha(b) !== img.sha256) throw new Error(`${img.file}: SHA-256 mismatch`);
  writeFileSync(out, b);
  console.log('ok', img.file, b.length);
}
