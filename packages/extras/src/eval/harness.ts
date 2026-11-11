// Agent eval harness. Tasks ask concrete reverse engineering questions about files in
// samples/extras. Ground truth was produced with independent reference tools (readelf,
// llvm-readobj, llvm-cxxfilt, pefile, lief, gguf-py, pylnk3, node) when the fixtures were
// generated, so scores measure the agent, not RevLens agreeing with itself.

import { ParseError } from '../util.js';
import { TASKS } from './tasks.js';

export type AnswerType = 'exact' | 'hex' | 'int' | 'set' | 'contains';
export interface EvalTask {
  id: string;
  question: string;
  /** path relative to the repository root */
  file: string;
  tags: string[];
  answerType: AnswerType;
  answer: string | number | string[];
  /** the reference tool and command that produced the answer */
  reference: string;
  /** RevLens tools that can answer it, for agents that want a hint */
  hint?: string[];
}
export type PublicTask = Omit<EvalTask, 'answer' | 'reference'>;

export const EVAL_TASKS: readonly EvalTask[] = TASKS;

/** Tasks without answers, safe to hand to an agent. */
export function publicTasks(tag?: string): PublicTask[] {
  return EVAL_TASKS.filter((t) => !tag || t.tags.includes(tag)).map(({ answer: _a, reference: _r, ...rest }) => rest);
}

const norm = (s: unknown): string => String(s ?? '').trim().toLowerCase().replace(/\s+/g, ' ').replace(/^["'`]|["'`]$/g, '');
function toBig(x: unknown): bigint | null {
  const s = norm(x).replace(/_/g, '');
  try { if (/^0x[0-9a-f]+$/.test(s)) return BigInt(s); if (/^[0-9a-f]+$/.test(s) && /[a-f]/.test(s)) return BigInt('0x' + s); if (/^\d+$/.test(s)) return BigInt(s); } catch { return null; }
  return null;
}
function toList(x: unknown): string[] {
  if (Array.isArray(x)) return x.map(norm).filter(Boolean);
  return String(x ?? '').split(/[\n,;]+/).map(norm).filter(Boolean);
}

export interface TaskScore { id: string; score: number; correct: boolean; expected: unknown; got: unknown; note?: string }
export interface EvalScore { agent?: string; tasks: number; answered: number; correct: number; score: number; accuracy: number; byTag: Record<string, { tasks: number; correct: number; score: number }>; results: TaskScore[] }

/** Score one answer. Sets get partial credit (F1); the rest are right or wrong. */
export function scoreTask(t: EvalTask, got: unknown): TaskScore {
  const base = { id: t.id, expected: t.answer, got };
  if (got === undefined || got === null || got === '') return { ...base, score: 0, correct: false, note: 'no answer' };
  switch (t.answerType) {
    case 'hex': case 'int': {
      const a = toBig(t.answer), b = toBig(got);
      const ok = a !== null && b !== null && a === b;
      return { ...base, score: ok ? 1 : 0, correct: ok };
    }
    case 'set': {
      const want = new Set(toList(t.answer)), have = new Set(toList(got));
      let tp = 0;
      for (const x of have) if (want.has(x)) tp++;
      const p = have.size ? tp / have.size : 0, r = want.size ? tp / want.size : 0;
      const f1 = p + r ? (2 * p * r) / (p + r) : 0;
      return { ...base, score: Math.round(f1 * 1000) / 1000, correct: f1 === 1, note: `precision ${p.toFixed(2)} recall ${r.toFixed(2)}` };
    }
    case 'contains': {
      const g = norm(got);
      const parts = toList(t.answer);
      const ok = parts.every((x) => g.includes(x));
      return { ...base, score: ok ? 1 : 0, correct: ok };
    }
    default: {
      // whitespace never changes meaning here: "a<b<int> >" and "a<b<int>>" are the same answer
      const ok = norm(t.answer) === norm(got) || norm(t.answer).replace(/\s+/g, '') === norm(got).replace(/\s+/g, '');
      return { ...base, score: ok ? 1 : 0, correct: ok };
    }
  }
}

/** Score a map of task id to answer. Unknown ids are rejected so typos are visible. */
export function scoreAnswers(answers: Record<string, unknown>, opts: { agent?: string; tasks?: readonly EvalTask[] } = {}): EvalScore {
  const tasks = opts.tasks ?? EVAL_TASKS;
  const ids = new Set(tasks.map((t) => t.id));
  const unknown = Object.keys(answers).filter((k) => !ids.has(k));
  if (unknown.length) throw new ParseError(`unknown task ids: ${unknown.slice(0, 10).join(', ')}`);
  const results = tasks.map((t) => scoreTask(t, answers[t.id]));
  const byTag: EvalScore['byTag'] = {};
  for (const [i, t] of tasks.entries()) {
    const r = results[i] as TaskScore;
    for (const tag of t.tags) {
      const b = (byTag[tag] ??= { tasks: 0, correct: 0, score: 0 });
      b.tasks++; b.correct += r.correct ? 1 : 0; b.score += r.score;
    }
  }
  for (const b of Object.values(byTag)) b.score = Math.round((b.score / b.tasks) * 1000) / 1000;
  const total = results.reduce((a, r) => a + r.score, 0);
  const correct = results.filter((r) => r.correct).length;
  return {
    agent: opts.agent, tasks: tasks.length, answered: results.filter((r) => r.note !== 'no answer').length, correct,
    score: Math.round((total / Math.max(1, tasks.length)) * 1000) / 1000, accuracy: Math.round((correct / Math.max(1, tasks.length)) * 1000) / 1000, byTag, results,
  };
}
