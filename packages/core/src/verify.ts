import type { Claim, ClaimResult, Report } from './types.js';
import { indexOf, asciiBytes, hexToBytes, hex } from './bytes.js';
import { detectFormat } from './format.js';
import { sha256 } from './hash.js';

/**
 * Check a claim an agent made about a file against the actual bytes.
 * Pass a report too for claims about parsed structure (imports, sections, components).
 * Every verdict carries the evidence, so a human can check it in seconds.
 */
export function verifyClaim(bytes: Uint8Array, claim: Claim, report?: Report): ClaimResult {
  const res = (verdict: ClaimResult['verdict'], reason: string, evidence: ClaimResult['evidence'] = []): ClaimResult => ({ verdict, claim, reason, evidence });
  switch (claim.kind) {
    case 'contains-string': {
      const a = indexOf(bytes, asciiBytes(claim.value));
      if (a >= 0) return res('VERIFIED', `Found the ASCII string at offset ${a}.`, [{ offset: a, length: claim.value.length, snippet: claim.value }]);
      const wide = new Uint8Array(claim.value.length * 2);
      for (let i = 0; i < claim.value.length; i++) wide[i * 2] = claim.value.charCodeAt(i) & 0xff;
      const w = indexOf(bytes, wide);
      if (w >= 0) return res('VERIFIED', `Found the string as UTF-16 at offset ${w}.`, [{ offset: w, length: wide.length, snippet: claim.value }]);
      return res('REFUTED', 'The string does not appear in the file as ASCII or UTF-16.');
    }
    case 'bytes-at': {
      const want = hexToBytes(claim.hex);
      if (claim.offset < 0 || claim.offset + want.length > bytes.length) return res('REFUTED', 'The offset is outside the file.');
      const got = hex(bytes, claim.offset, claim.offset + want.length);
      return got === hex(want) ? res('VERIFIED', 'The bytes match exactly.', [{ offset: claim.offset, length: want.length, snippet: got }])
        : res('REFUTED', `The bytes at ${claim.offset} are ${got}.`, [{ offset: claim.offset, length: want.length, snippet: got }]);
    }
    case 'format-is': {
      const f = detectFormat(bytes, report?.file.name);
      return f === claim.format ? res('VERIFIED', `Magic bytes identify the file as ${f}.`) : res('REFUTED', `Magic bytes identify the file as ${f}, not ${claim.format}.`);
    }
    case 'sha256-is': {
      const h = sha256(bytes);
      return h === claim.value.toLowerCase() ? res('VERIFIED', 'The SHA-256 matches.') : res('REFUTED', `The SHA-256 is ${h}.`);
    }
    case 'imports-symbol': {
      if (!report) return res('UNKNOWN', 'Pass the analysis report to check imports.');
      for (const i of report.imports) {
        if (claim.library && i.library.toLowerCase() !== claim.library.toLowerCase()) continue;
        const s = i.symbols.find((x) => x === claim.symbol || x.startsWith(claim.symbol + ' '));
        if (s) return res('VERIFIED', `${i.library} imports ${s}.`, [{ snippet: `${i.library}!${s}` }]);
      }
      if (indexOf(bytes, asciiBytes(claim.symbol)) >= 0) return res('UNKNOWN', 'The name appears in the file but not in the parsed import table. It may be resolved at run time.');
      return res('REFUTED', 'The symbol is not in the import table or anywhere in the file.');
    }
    case 'has-section': {
      if (!report) return res('UNKNOWN', 'Pass the analysis report to check sections.');
      const s = report.sections.find((x) => x.name === claim.name);
      return s ? res('VERIFIED', `Section ${s.name} is at offset ${s.offset}, ${s.size} bytes.`, [{ offset: s.offset, length: s.size, snippet: s.name }])
        : res('REFUTED', `No section is named ${claim.name}. Sections: ${report.sections.map((x) => x.name).slice(0, 12).join(', ') || 'none'}.`);
    }
    case 'uses-component': {
      if (!report) return res('UNKNOWN', 'Pass the analysis report to check components.');
      const all = [report, ...(report.children ?? [])].flatMap((r) => r.components);
      const c = all.find((x) => x.name === claim.name.toLowerCase());
      if (!c) return res('REFUTED', `No evidence of ${claim.name} was found.`);
      if (claim.version && c.version && c.version !== claim.version) return res('REFUTED', `${c.name} is present at version ${c.version}, not ${claim.version}.`, c.evidence);
      return res(claim.version && !c.version ? 'UNKNOWN' : 'VERIFIED', c.version ? `${c.name} ${c.version} is present.` : `${c.name} is present, version unknown.`, c.evidence);
    }
  }
}
