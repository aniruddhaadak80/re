// Builds generated.js (introspection JSON as a JSON.parse string, and a precompiled GraphQL
// document like babel-plugin-graphql-tag emits) with graphql-js, then bundles app.js with esbuild.
import { readFileSync, writeFileSync } from 'node:fs';
import { buildSchema, introspectionFromSchema, parse } from 'graphql';
import { build } from 'esbuild';
const here = new URL('.', import.meta.url).pathname;
const sdl = readFileSync(here + '../proto/schema.graphql', 'utf8');
const intro = introspectionFromSchema(buildSchema(sdl));
const doc = parse('query ListUsers($pageSize: Int) { users(pageSize: $pageSize) { users { id email } nextPageToken } }', { noLocation: true });
writeFileSync(here + 'generated.js', `export const introspection = JSON.parse(${JSON.stringify(JSON.stringify(intro))});\nexport const precompiled = ${JSON.stringify(doc)};\n`);
writeFileSync(here + '../../contracts/introspection.json', JSON.stringify(intro, null, 1));
await build({ entryPoints: [here + 'app.js'], bundle: true, minify: true, format: 'esm', outfile: here + '../../contracts/app.bundle.min.js', logLevel: 'warning' });
console.log('ok');
