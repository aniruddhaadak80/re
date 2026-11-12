// LZFSE placeholder: decoding is not implemented yet, so ULFO chunks are reported as unsupported.
import { FormatError } from './util.js';

export class UnsupportedCodec extends FormatError {}

export function lzfseDecompress(_input: Uint8Array, _expected: number): Uint8Array {
  throw new UnsupportedCodec('LZFSE chunks are not decoded yet');
}
