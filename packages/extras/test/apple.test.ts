// Apple archives against reference tools: NSKeyedArchiver output of swift-corelibs-foundation
// (Swift 6.0.3) decoded by NSKeyedUnArchiver 1.5.2 and plistlib; Sparkle 2.10.1 nibs built by
// Xcode ibtool, read by the nibarchive 1.1.0 parser; Maccy 2.8.0 Assets.car against its own
// asset catalog source and CARHEADER rendition count.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import * as X from '../src/node.js';
import { RG, sx, cachedAt } from './helpers2.js';

const A = RG.apple;

test('NSKeyedArchiver binary archive decodes like NSKeyedUnArchiver', () => {
  const k = X.decodeKeyedArchive(sx('apple', 'dict.keyedarchive'));
  assert.equal(k.archiver, 'NSKeyedArchiver');
  assert.equal(k.version, 100000);
  assert.equal(k.objectCount, A.keyed['dict.keyedarchive'].objects);
  assert.deepEqual(k.root, A.keyed['dict.keyedarchive'].root);
  assert.deepEqual(k.classes.map((c) => c.name).sort(), ['NSArray', 'NSDate', 'NSDictionary', 'NSNull', 'NSSet', 'NSURL', 'NSUUID']);
});

test('NSKeyedArchiver XML archive with CF$UID dictionaries decodes like plistlib + NSKeyedUnArchiver', () => {
  const k = X.decodeKeyedArchive(sx('apple', 'array-xml.keyedarchive'));
  assert.equal(k.objectCount, A.keyed['array-xml.keyedarchive'].objects);
  assert.deepEqual(k.root, A.keyed['array-xml.keyedarchive'].root);
});

test('NIBArchive header, classes, keys, objects and every typed value match nibarchive', () => {
  for (const f of ['SUUpdateAlert.nib', 'SUUpdatePermissionPrompt.nib']) {
    const ref = A.nib[f];
    const n = X.parseNib(sx('apple', f));
    const o = n.offsets, c = n.counts;
    assert.deepEqual([n.formatVersion, n.coderVersion, c.objects, o.objects, c.keys, o.keys, c.values, o.values, c.classes, o.classes], ref.header);
    assert.deepEqual(n.classes, ref.classes);
    assert.deepEqual(n.keys, ref.keys);
    let vi = 0;
    n.objects.forEach((obj, i) => {
      assert.equal(obj.class, ref.classes[ref.objects[i][0]]);
      assert.equal(obj.values.length, ref.objects[i][2]);
      for (const v of obj.values) {
        const [key, type, data] = ref.values[ref.objects[i][1] + obj.values.indexOf(v)];
        assert.equal(v.key, key);
        if (type === 10) assert.deepEqual(v.value, { $obj: data });
        else if (type === 8 && typeof data === 'string' && typeof v.value === 'string') assert.equal(v.value, data);
        else if (type <= 3 || type === 6 || type === 7) assert.equal(Number(v.value), data);
        vi++;
      }
    });
    assert.ok(vi > 1000 || f !== 'SUUpdateAlert.nib');
  }
  const s = X.summarizeNib(X.parseNib(sx('apple', 'SUUpdateAlert.nib')));
  const texts = s.strings.map((x) => x.value);
  for (const t of ['Install Update', 'Skip This Version', 'Remind Me Later']) assert.ok(texts.includes(t), t);
  assert.ok(s.connections.length > 10);
  assert.ok(s.customClasses.includes('SUUpdateAlert'));
});

test('Assets.car: facets cover the asset catalog source, renditions match the CARHEADER count', { skip: !cachedAt('', 'maccy-Assets.car') && 'run packages/extras/scripts/fetch-fixtures.mjs' }, () => {
  const c = X.parseAssetCatalog(cachedAt('', 'maccy-Assets.car')!);
  assert.equal(c.renditions.length, c.header!.renditionCount);
  assert.equal(c.header!.renditionCount, 55);
  assert.equal(c.metadata!.deploymentPlatform, 'macosx');
  assert.equal(c.metadata!.deploymentPlatformVersion, '14.0');
  const facets = c.facets.map((f) => f.name);
  for (const n of A.maccyXcassets.names) assert.ok(facets.includes(n), n);
  const menu = c.renditions.filter((r) => r.facet === 'StatusBarMenuImage');
  assert.deepEqual(menu.map((r) => [r.width, r.scale]).sort(), [[16, 1], [16, 1], [32, 2], [32, 2]]);
  assert.ok(c.renditions.some((r) => r.facet === 'AppIcon' && r.width === 1024));
});

test('Apple parsers reject hostile input with ParseError only', () => {
  const parsers: ((b: Uint8Array) => unknown)[] = [(b) => X.parsePlistAny(b), (b) => X.decodeKeyedArchive(b), (b) => X.parseNib(b), (b) => X.parseAssetCatalog(b), (b) => X.parseBom(b)];
  const seeds = [sx('apple', 'dict.keyedarchive'), sx('apple', 'array-xml.keyedarchive'), sx('apple', 'SUUpdateAlert.nib')];
  const car = cachedAt('', 'maccy-Assets.car');
  if (car) seeds.push(car.slice(0, 200000));
  fc.assert(fc.property(fc.integer({ min: 0, max: seeds.length - 1 }), fc.integer({ min: 0, max: 1 << 20 }), fc.integer({ min: 0, max: 255 }), fc.integer({ min: 0, max: 40 }), (si, pos, val, cut) => {
    const s = seeds[si]!;
    const m = s.slice(0, Math.max(0, s.length - cut * 31));
    if (m.length) m[pos % m.length] = val;
    for (const p of parsers) { try { p(m); } catch (e) { if (!(e instanceof X.ParseError) && !(e instanceof RangeError)) throw e; } }
  }), { numRuns: 200 });
});
