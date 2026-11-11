import { greet } from "./lib.ts";
console.log(greet("bundle"), (globalThis as any).Deno?.version?.deno ?? (globalThis as any).Bun?.version);
