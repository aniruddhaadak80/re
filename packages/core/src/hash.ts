// Pure TypeScript hashing: md5, sha1, sha256, plus a TLSH-like locality digest
// and a CTPH (context triggered piecewise hash) for similarity. No Node, no WebCrypto,
// so it runs identically in the browser, a worker and Node.

function rotl(x: number, c: number): number { return (x << c) | (x >>> (32 - c)); }
function rotr(x: number, c: number): number { return (x >>> c) | (x << (32 - c)); }
function toHex(words: number[]): string {
  let s = '';
  for (const w of words) s += (w >>> 0).toString(16).padStart(8, '0');
  return s;
}

export function md5(input: Uint8Array): string {
  const s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const K = new Int32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const ml = input.length;
  const withOne = ml + 1;
  const padLen = ((withOne + 8 + 63) & ~63);
  const msg = new Uint8Array(padLen);
  msg.set(input);
  msg[ml] = 0x80;
  const bits = ml * 8;
  const dv = new DataView(msg.buffer);
  dv.setUint32(padLen - 8, bits >>> 0, true);
  dv.setUint32(padLen - 4, Math.floor(bits / 4294967296), true);
  for (let off = 0; off < padLen; off += 64) {
    const M = new Int32Array(16);
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + (K[i] as number) + (M[g] as number)) | 0;
      A = D; D = C; C = B;
      B = (B + rotl(F, s[i] as number)) | 0;
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
  }
  const out = (x: number) => {
    let r = '';
    for (let i = 0; i < 4; i++) r += ((x >>> (i * 8)) & 0xff).toString(16).padStart(2, '0');
    return r;
  };
  return out(a0) + out(b0) + out(c0) + out(d0);
}

export function sha1(input: Uint8Array): string {
  let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
  const ml = input.length * 8;
  const withOne = input.length + 1;
  const padLen = ((withOne + 8 + 63) & ~63);
  const msg = new Uint8Array(padLen);
  msg.set(input); msg[input.length] = 0x80;
  const dv = new DataView(msg.buffer);
  dv.setUint32(padLen - 8, Math.floor(ml / 4294967296));
  dv.setUint32(padLen - 4, ml >>> 0);
  const w = new Int32Array(80);
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4);
    for (let i = 16; i < 80; i++) w[i] = rotl((w[i - 3] as number) ^ (w[i - 8] as number) ^ (w[i - 14] as number) ^ (w[i - 16] as number), 1);
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f: number, k: number;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
      else { f = b ^ c ^ d; k = 0xCA62C1D6; }
      const t = (rotl(a, 5) + f + e + k + (w[i] as number)) | 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = t;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
  }
  return toHex([h0, h1, h2, h3, h4]);
}

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

export function sha256(input: Uint8Array): string {
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
    h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const ml = input.length * 8;
  const withOne = input.length + 1;
  const padLen = ((withOne + 8 + 63) & ~63);
  const msg = new Uint8Array(padLen);
  msg.set(input); msg[input.length] = 0x80;
  const dv = new DataView(msg.buffer);
  dv.setUint32(padLen - 8, Math.floor(ml / 4294967296));
  dv.setUint32(padLen - 4, ml >>> 0);
  const w = new Uint32Array(64);
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15] as number, y = w[i - 2] as number;
      const s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
      const s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10);
      w[i] = ((w[i - 16] as number) + s0 + (w[i - 7] as number) + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + (SHA256_K[i] as number) + (w[i] as number)) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  return toHex([h0, h1, h2, h3, h4, h5, h6, h7]);
}

/**
 * A compact locality sensitive digest in the spirit of TLSH. It buckets the
 * distribution of sliding 3-grams into a fixed histogram and quantizes it. Two
 * similar files produce digests with a small Hamming distance. This is our own
 * implementation, not byte compatible with the reference TLSH.
 */
export function tlshLike(input: Uint8Array): string {
  if (input.length < 32) return '';
  const buckets = new Uint32Array(48);
  const salt = [2, 3, 5, 7, 11, 13];
  for (let i = 2; i < input.length; i++) {
    const a = input[i] as number, b = input[i - 1] as number, c = input[i - 2] as number;
    for (let s = 0; s < 6; s++) {
      const v = (a * (salt[s] as number) + b * 31 + c) & 0xff;
      buckets[v % 48] = (buckets[v % 48] as number) + 1;
    }
  }
  let sum = 0;
  for (const v of buckets) sum += v;
  const mean = sum / buckets.length;
  let out = '';
  for (let i = 0; i < buckets.length; i += 4) {
    let nibble = 0;
    for (let j = 0; j < 4; j++) nibble = (nibble << 1) | ((buckets[i + j] as number) > mean ? 1 : 0);
    out += nibble.toString(16);
  }
  return 'T1' + out;
}

export function tlshDistance(a: string, b: string): number {
  if (!a || !b || a.length !== b.length) return -1;
  let d = 0;
  for (let i = 2; i < a.length; i++) {
    let x = parseInt(a[i] as string, 16) ^ parseInt(b[i] as string, 16);
    while (x) { d += x & 1; x >>= 1; }
  }
  return d;
}

/**
 * Context triggered piecewise hash (ssdeep family idea). Splits the input at
 * content defined boundaries using a rolling hash, then hashes each piece to a
 * base64 character. Comparable with ctphSimilarity below.
 */
export function ctph(input: Uint8Array, blockSize = 0): string {
  if (!blockSize) { blockSize = 3; while (blockSize * 64 < input.length) blockSize *= 2; }
  const b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  // ssdeep style rolling hash over a 7 byte window.
  const W = 7;
  const window = new Uint8Array(W);
  let h1 = 0, h2 = 0, h3 = 0, n = 0;
  let h = 0x28021967;
  let out = '';
  for (let i = 0; i < input.length; i++) {
    const c = input[i] as number;
    h2 = (h2 - h1 + W * c) >>> 0;
    h1 = (h1 + c - (window[n % W] as number)) >>> 0;
    window[n % W] = c; n++;
    h3 = ((h3 << 5) ^ c) >>> 0;
    const roll = (h1 + h2 + h3) >>> 0;
    h = (Math.imul(h, 0x01000193) ^ c) >>> 0;
    if (roll % blockSize === blockSize - 1) {
      out += b64[h % 64];
      h = 0x28021967;
    }
  }
  out += b64[h % 64];
  return `${blockSize}:${out}`;
}

export function ctphSimilarity(a: string, b: string): number {
  const sa = a.split(':')[1] ?? '', sb = b.split(':')[1] ?? '';
  if (!sa || !sb) return 0;
  const grams = (s: string) => {
    const set = new Set<string>();
    for (let i = 0; i + 3 <= s.length; i++) set.add(s.slice(i, i + 3));
    return set;
  };
  const A = grams(sa), B = grams(sb);
  if (A.size === 0 || B.size === 0) return 0;
  let inter = 0;
  for (const g of A) if (B.has(g)) inter++;
  return Math.round((inter / (A.size + B.size - inter)) * 100);
}
