import { c } from './c.js';
export function lazyThing(s, v) { return `${s}:${v}:${c()}`; }
