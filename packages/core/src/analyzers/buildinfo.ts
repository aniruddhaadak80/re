import type { Analyzer, Component } from '../types.js';
import { indexOf, asciiBytes, decodeUtf8 } from '../bytes.js';

// Go build info magic, see go/src/debug/buildinfo.
const GO_MAGIC = asciiBytes('\xff Go buildinf:');

export const buildinfoAnalyzer: Analyzer = {
  id: 'buildinfo',
  title: 'Go and Rust build info',
  description: 'Reads embedded Go build info and cargo-auditable dependency data from native binaries.',
  applies: (ctx) => ctx.format === 'elf' || ctx.format === 'pe' || ctx.format === 'dotnet' || ctx.format === 'macho',
  run(ctx) {
    const { bytes, report } = ctx;
    const comps: Component[] = [];

    // Go: find the module/version block which follows the magic. Go version is right after the header.
    const go = indexOf(bytes, GO_MAGIC);
    if (go >= 0) {
      // The textual module table appears as a run of printable text after the header.
      const region = decodeUtf8(bytes.subarray(go, Math.min(bytes.length, go + 65536)));
      const ver = /go1\.\d+(?:\.\d+)?/.exec(region);
      if (ver) {
        report.meta.goVersion = ver[0];
        report.findings.push({
          id: 'buildinfo.go', analyzer: 'buildinfo', title: `Built with ${ver[0]}`, severity: 'info',
          detail: `This is a Go binary compiled with ${ver[0]}. Module and dependency names are often recoverable from the embedded build info.`,
          evidence: [{ offset: go, length: GO_MAGIC.length, snippet: 'Go buildinf' }], tags: ['go'],
        });
      }
      const mainPath = /\bpath\t([^\n]+)/.exec(region)?.[1];
      const mainMod = /\bmod\t([^\t\n]+)\t([^\t\n]*)/.exec(region);
      const settings: Record<string, string> = {};
      for (const b of region.matchAll(/\bbuild\t([\w.-]+)=([^\n]*)/g)) settings[b[1] as string] = (b[2] as string).slice(0, 300);
      report.meta.goBuild = { path: mainPath, module: mainMod?.[1], moduleVersion: mainMod?.[2], settings };
      // dep lines look like: dep\tgithub.com/foo/bar\tv1.2.3\th1:...
      const depRe = /(?:^|\n)dep\t([^\t\n]+)\t(v[0-9][^\t\n]*)/g;
      let m: RegExpExecArray | null;
      while ((m = depRe.exec(region)) && comps.length < 400) {
        comps.push({ name: m[1] as string, version: m[2] as string, ecosystem: 'go',
          purl: `pkg:golang/${encodeURIComponent(m[1] as string)}@${m[2]}`, confidence: 0.9,
          evidence: [{ offset: go + m.index, length: m[0].length }] });
      }
    }

    // Rust: cargo-auditable embeds a zlib JSON in a .dep-v0 section; fall back to version strings.
    const rustc = /rustc\/([0-9a-f]{40})|rustc-(\d+\.\d+\.\d+)/.exec(decodeUtf8(bytes.subarray(0, Math.min(bytes.length, 2_000_000))));
    if (rustc) {
      report.meta.rust = rustc[2] ?? rustc[1];
      report.findings.push({
        id: 'buildinfo.rust', analyzer: 'buildinfo', title: 'Rust binary', severity: 'info',
        detail: 'Found rustc build markers. If the project used cargo-auditable, the dependency tree is embedded and recoverable.',
        evidence: [], tags: ['rust'],
      });
    }

    if (comps.length) {
      report.components.push(...comps);
      report.findings.push({
        id: 'buildinfo.gomods', analyzer: 'buildinfo', title: `Recovered ${comps.length} Go modules`, severity: 'info',
        detail: 'The Go build info lists the module dependencies and versions. These feed the software bill of materials and the vulnerability lookup.',
        evidence: [], tags: ['sbom', 'go'],
      });
    }
  },
};
