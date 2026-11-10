// Decompression through the standard DecompressionStream API, which exists in
// modern browsers, Web Workers, Deno, Bun and Node 18+. No dependency needed.

type Fmt = 'gzip' | 'deflate' | 'deflate-raw';

export async function decompress(data: Uint8Array, format: Fmt, maxOut = 256 * 1024 * 1024): Promise<Uint8Array> {
  const DS = (globalThis as unknown as { DecompressionStream?: new (f: string) => TransformStream<Uint8Array, Uint8Array> }).DecompressionStream;
  if (!DS) throw new Error('DecompressionStream is not available in this runtime');
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DS(format));
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) {
      total += value.length;
      if (total > maxOut) { await reader.cancel(); throw new Error(`decompressed size passed the ${maxOut} byte safety limit`); }
      chunks.push(value);
    }
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}
