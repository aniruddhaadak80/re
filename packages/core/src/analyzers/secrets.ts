import type { Analyzer, Severity } from '../types.js';
import { entropy, asciiBytes } from '../bytes.js';

interface Rule { id: string; title: string; re: RegExp; severity: Severity; verify?: (m: string) => boolean }

function shannonOfString(s: string): number { return entropy(asciiBytes(s)); }

const RULES: Rule[] = [
  { id: 'aws-akid', title: 'AWS access key id', re: /\b(AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b/, severity: 'high' },
  { id: 'aws-secret', title: 'AWS secret access key', re: /\baws_secret[^\n]{0,20}['"]?([A-Za-z0-9/+=]{40})['"]?/i, severity: 'critical' },
  { id: 'gcp-key', title: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/, severity: 'high' },
  { id: 'github-pat', title: 'GitHub token', re: /\b(ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{36,}\b/, severity: 'critical' },
  { id: 'slack', title: 'Slack token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, severity: 'high' },
  { id: 'stripe', title: 'Stripe secret key', re: /\b(sk|rk)_(live|test)_[0-9A-Za-z]{16,}\b/, severity: 'critical' },
  { id: 'openai', title: 'OpenAI API key', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,200}T3BlbkFJ[A-Za-z0-9_-]{20,200}\b/, severity: 'critical' },
  { id: 'anthropic', title: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{90,}\b/, severity: 'critical' },
  { id: 'google-oauth', title: 'Google OAuth client secret', re: /\bGOCSPX-[0-9A-Za-z_-]{28}\b/, severity: 'high' },
  { id: 'npm', title: 'npm access token', re: /\bnpm_[0-9A-Za-z]{36}\b/, severity: 'high' },
  { id: 'jwt', title: 'JSON Web Token', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, severity: 'medium' },
  { id: 'privatekey', title: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA |ENCRYPTED )?PRIVATE KEY-----(?:\\r?\\n|\r?\n)[A-Za-z0-9+\/=\r\n\\]{120,}/, severity: 'critical' },
  { id: 'slack-webhook', title: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]+\/B[0-9A-Z]+\/[0-9A-Za-z]+/, severity: 'high' },
  { id: 'twilio', title: 'Twilio account SID', re: /\bAC[0-9a-fA-F]{32}\b/, severity: 'medium' },
  { id: 'sendgrid', title: 'SendGrid API key', re: /\bSG\.[\w-]{20,}\.[\w-]{20,}\b/, severity: 'high' },
  { id: 'generic-secret', title: 'Hardcoded secret assignment', severity: 'medium',
    re: /(?:api[_-]?key|secret|passwd|password|token|auth)['"]?\s*[:=]\s*['"]([^'"\s]{12,64})['"]/i,
    verify: (m) => shannonOfString(m) > 3.2 && !/^[a-z_]+$/i.test(m) && !/(example|changeme|your[-_]?key|xxxx|placeholder|<[^>]+>)/i.test(m) },
];

function redact(s: string): string { return s.length <= 8 ? '****' : `${s.slice(0, 4)}...${s.slice(-2)} (${s.length} chars)`; }

export const secretsAnalyzer: Analyzer = {
  id: 'secrets',
  title: 'Secrets',
  description: 'Finds hardcoded credentials: cloud keys, tokens, private keys and high entropy secret assignments. Values are redacted in the report.',
  applies: (ctx) => !!ctx.text || ctx.report.strings.length > 0,
  run(ctx) {
    const { report } = ctx;
    const haystacks: { text: string; base: number }[] = ctx.text
      ? [{ text: ctx.text.length > 12_000_000 ? ctx.text.slice(0, 12_000_000) : ctx.text, base: 0 }]
      : report.strings.map((s) => ({ text: s.value, base: s.offset }));
    const seen = new Set<string>();
    for (const rule of RULES) {
      for (const h of haystacks) {
        const re = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : rule.re.flags + 'g');
        let m: RegExpExecArray | null;
        let hits = 0;
        while ((m = re.exec(h.text)) && hits < 20) {
          hits++;
          const captured = (m[1] ?? m[0]);
          if (rule.verify && !rule.verify(captured)) continue;
          const key = `${rule.id}:${captured}`;
          if (seen.has(key)) continue;
          seen.add(key);
          report.findings.push({
            id: `secret.${rule.id}.${seen.size}`, analyzer: 'secrets', title: `${rule.title} found`, severity: rule.severity,
            detail: `A value matching a ${rule.title} is present (${redact(captured)}). Treat it as leaked: rotate it and remove it from the source and history.`,
            evidence: [{ offset: h.base + m.index, length: m[0].length, snippet: redact(captured) }],
            tags: ['secret', 'credential'], attack: ['T1552.001'],
          });
        }
      }
    }
    const count = report.findings.filter((f) => f.analyzer === 'secrets').length;
    if (count) report.meta.secrets = count;
  },
};
