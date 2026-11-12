// Entry of the import graph fixture: static, dynamic, TypeScript and CommonJS imports.
import { startA } from './a.js';
import { slug } from './util/strings.js';
import { debounce } from 'lodash-es';
import legacy from './legacy.cjs';

export async function main(name) {
  startA();
  const s = slug(name);
  const { lazyThing } = await import('./lazy.js');
  return debounce(() => lazyThing(s, legacy.version), 10);
}
