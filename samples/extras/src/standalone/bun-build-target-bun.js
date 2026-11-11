// @bun
// lib.ts
var greet = (n) => `hello ${n}`;

// app.ts
console.log(greet("bundle"), globalThis.Deno?.version?.deno ?? globalThis.Bun?.version);
