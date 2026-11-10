import type { Analyzer, Severity } from '../types.js';
import { scanRules, STARTER_RULES } from '../rules/yaralite.js';

const SEV = new Set(['info', 'low', 'medium', 'high', 'critical']);

export const yaraAnalyzer: Analyzer = {
  id: 'yara',
  title: 'Rules (yara-lite)',
  description: 'Runs the built in rule pack plus your own YARA style rules, in pure TypeScript.',
  applies: (ctx) => ctx.bytes.length > 0 && ctx.bytes.length <= 64 * 1024 * 1024,
  run(ctx) {
    const text = STARTER_RULES + '\n' + (ctx.options.rules ?? '');
    const matches = scanRules(ctx.bytes, text);
    ctx.report.meta.ruleMatches = matches.map((m) => m.rule);
    for (const m of matches) {
      const sev = (SEV.has(m.meta.severity ?? '') ? m.meta.severity : 'medium') as Severity;
      ctx.report.findings.push({
        id: `rule.${m.rule}`, analyzer: 'yara', title: `Rule ${m.rule} matched`, severity: sev,
        detail: m.meta.description ?? `The rule ${m.rule} matched this file.`,
        evidence: m.strings.slice(0, 6).map((s) => ({ offset: s.offset, length: s.length, snippet: `${s.id} ${s.snippet}` })),
        tags: m.tags, attack: m.meta.attack ? [m.meta.attack] : undefined,
      });
    }
  },
};
