// Java class parsing and disassembly checked against JDK 17 javap -c -p output.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { javap, parseClass, openZip, readEntry, javaFloat, mobileJavaClass } from '../src/node.js';
import { bytes, gzText, sample } from './helpers.js';

test('Hello.class: javap -c -p output is identical', () => {
  const want = readFileSync(sample('expected', 'Hello.javap.txt'), 'utf8').trimEnd();
  const cf = parseClass(bytes('java', 'Hello.class'));
  assert.equal(cf.major, 52);
  assert.equal(cf.javaVersion, '8');
  assert.equal(javap(cf), want);
});

test('commons-cli 1.6.0: every class disassembles identically to javap -c -p', async () => {
  const zip = openZip(bytes('java', 'commons-cli-1.6.0.jar'));
  const parts: string[] = [];
  let n = 0;
  for (const e of zip.entries) {
    if (!e.name.endsWith('.class') || e.name.includes('module-info')) continue;
    parts.push(javap(parseClass(await readEntry(zip, e))));
    n++;
  }
  assert.ok(n > 20, `${n} classes`);
  const want = gzText('expected', 'commons-cli-1.6.0.javap.txt.gz').trimEnd().split('\n');
  const got = parts.join('\n').split('\n');
  assert.equal(got.length, want.length);
  for (let i = 0; i < want.length; i++) assert.equal(got[i], want[i], `line ${i + 1}`);
});

test('Java float and double formatting follows Float.toString and Double.toString', () => {
  assert.equal(javaFloat(Math.fround(3.4028234663852886e38), 'f'), '3.4028235E38f');
  assert.equal(javaFloat(Math.fround(Math.PI), 'f'), '3.1415927f');
  assert.equal(javaFloat(2147483647, 'd'), '2.147483647E9d');
  assert.equal(javaFloat(1.5, 'd'), '1.5d');
  assert.equal(javaFloat(0.001, 'd'), '0.001d');
  assert.equal(javaFloat(1e-4, 'd'), '1.0E-4d');
  assert.equal(javaFloat(Number.NaN, 'f'), 'NaNf');
});

test('mobile_java_class lists a JAR and disassembles one method', async () => {
  const path = sample('java', 'commons-cli-1.6.0.jar');
  const list = await mobileJavaClass({ path, limit: 500 });
  assert.ok(list.classCount && list.classCount > 20);
  assert.ok(list.classes?.items.some((c) => c.path === 'org/apache/commons/cli/Option.class'));
  const one = await mobileJavaClass({ path, class: 'org.apache.commons.cli.Option', method: 'hasArg' });
  assert.equal(one.declaration, 'public class org.apache.commons.cli.Option implements java.lang.Cloneable,java.io.Serializable');
  assert.ok(one.disassembly?.[0]?.includes('    Code:'));
  const hello = await mobileJavaClass({ path: sample('java', 'Hello.class'), method: 'reflect' });
  assert.ok(hello.calls?.some((c) => c.ref === 'Method java/lang/Class.forName:(Ljava/lang/String;)Ljava/lang/Class;'));
});
