import type { Claim, ClaimResult, Report, RuleMatch } from '@revlens/core';

export type WorkerRequest =
  | { type: 'analyze'; id: string; name: string; buffer: ArrayBuffer; rules?: string }
  | { type: 'rules'; id: string; fileId: string; text: string }
  | { type: 'verify'; id: string; fileId: string; claim: Claim }
  | { type: 'forget'; fileId: string };

export type WorkerResponse =
  | { type: 'progress'; id: string; analyzer: string; phase: 'start' | 'end'; depth: number; file: string; ms?: number }
  | { type: 'done'; id: string; report: Report }
  | { type: 'error'; id: string; message: string }
  | { type: 'rules-result'; id: string; matches?: RuleMatch[]; error?: string }
  | { type: 'verify-result'; id: string; result?: ClaimResult; error?: string };
