// Runs an analyzer's checks in parallel as named tasks. Each task resolves its
// API key, runs with a timeout, turns its answer into findings, and reports
// to the progress tracker as soon as it is done. A check that could not run
// becomes a "Skipped" finding with the reason (no key, quota, timeout, error).
import type { AnalysisDetail, AnalysisType, Indicator, PivotLink, PlannedTask } from '@/types';
import { getService, type ServiceId } from '@/lib/services';
import type { AnalysisContext } from './context';
import { SOURCE_TIMEOUT_SECONDS } from '@/lib/bulk-limits';

const DEFAULT_TIMEOUT_MS = SOURCE_TIMEOUT_SECONDS * 1000;

export interface TaskOutput {
  indicators: Indicator[];
  details: Record<string, AnalysisDetail>;
  /** Set false when the source replied but the answer wasn't usable (e.g. refused) */
  answered?: boolean;
}

export interface TaskTools {
  /** Key for `service`, when the task has one */
  key?: string;
  /** For tasks covering several sources: call once per source as it answers */
  report: (answered: boolean) => void;
  /** Wait for another task's value */
  wait: <V>(id: string) => Promise<V | null>;
}

export interface TaskSpec<T> {
  id: string;
  /** Row name in the findings table ("Fraud score", "DNS resolution") */
  label: string;
  /** Source column ("IPQualityScore") */
  source: string;
  /** How many sources this task covers (default 1) */
  sources?: number;
  /** The task calls report() itself for each of its sources */
  selfReport?: boolean;
  /** Per-user key (resolved user key → server key → skip) */
  service?: ServiceId;
  /** Key only the server admin can set */
  serverKeyEnv?: string;
  timeoutMs?: number;
  /** Don't run; show as skipped with this reason */
  skip?: string;
  run: (tools: TaskTools) => Promise<T | null>;
  build?: (value: T, out: TaskOutput) => void;
  /** Findings when the source answered with nothing (default: "No answer" skip) */
  onEmpty?: (out: TaskOutput) => void;
}

class TimeoutError extends Error {}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      timer = setTimeout(() => reject(new TimeoutError()), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

export function skippedIndicator(id: string, label: string, source: string, reason: string): Indicator {
  return { id: `skipped-${id}`, name: label, status: 'unknown', description: reason, severity: 'low', source };
}

export class TaskRunner {
  private specs: TaskSpec<unknown>[] = [];
  private promises = new Map<string, Promise<unknown>>();
  private outputs = new Map<string, TaskOutput>();
  private values = new Map<string, unknown>();
  /** Services that already have a "skipped" row */
  private skippedServices = new Set<string>();

  constructor(private ctx: AnalysisContext) {}

  add<T>(spec: TaskSpec<T>): this {
    this.specs.push(spec as TaskSpec<unknown>);
    return this;
  }

  value<T>(id: string): T | null {
    return (this.values.get(id) as T | undefined) ?? null;
  }

  /** Plans everything, runs it all in parallel, resolves when every task is done. */
  async run(target: string, kind: AnalysisType, pivots: PivotLink[] = []): Promise<void> {
    const planned: PlannedTask[] = this.specs.map((s) => ({
      id: s.id,
      label: s.label,
      source: s.source,
      sources: s.sources ?? 1,
    }));
    this.ctx.progress.plan(target, kind, planned, pivots);
    for (const spec of this.specs) this.promises.set(spec.id, this.exec(spec));
    await Promise.all(this.promises.values());
  }

  /** Findings and raw-data panels, in the order the tasks were added. */
  collect(): TaskOutput {
    const out: TaskOutput = { indicators: [], details: {} };
    for (const spec of this.specs) {
      const o = this.outputs.get(spec.id);
      if (!o) continue;
      out.indicators.push(...o.indicators);
      Object.assign(out.details, o.details);
    }
    return out;
  }

  private async exec(spec: TaskSpec<unknown>): Promise<unknown> {
    const out: TaskOutput = { indicators: [], details: {} };
    const planned = spec.sources ?? 1;
    let reported = 0;
    let answered = false;
    let state: 'done' | 'skipped' = 'done';
    const report = (ok: boolean) => {
      if (reported >= planned) return;
      reported++;
      this.ctx.progress.source(ok);
    };
    const skip = (reason: string) => {
      state = 'skipped';
      out.indicators.push(skippedIndicator(spec.service ?? spec.id, spec.label, spec.source, reason));
      if (spec.service) this.skippedServices.add(spec.service);
    };

    let value: unknown = null;
    try {
      let key: string | undefined;
      if (spec.skip) {
        skip(spec.skip);
        return null;
      }
      if (spec.serverKeyEnv && !process.env[spec.serverKeyEnv]?.trim()) {
        skip(`Not set up on this server (no ${spec.source} key).`);
        return null;
      }
      if (spec.service) {
        const grant = await this.ctx.keys.acquire(spec.service);
        if (!grant.ok) {
          skip(grant.reason);
          return null;
        }
        key = grant.key;
      }
      const timeoutMs = spec.timeoutMs ?? DEFAULT_TIMEOUT_MS;
      value = await withTimeout(
        spec.run({ key, report, wait: <V,>(id: string) => (this.promises.get(id) ?? Promise.resolve(null)) as Promise<V | null> }),
        timeoutMs
      );
      if (value === null || value === undefined) {
        if (spec.onEmpty) {
          answered = true;
          spec.onEmpty(out);
        } else {
          skip(`No answer from ${spec.source}.`);
        }
      } else {
        spec.build?.(value, out);
        answered = out.answered !== false;
      }
      return value;
    } catch (error) {
      if (error instanceof TimeoutError) {
        skip(`Timed out after ${Math.round((spec.timeoutMs ?? DEFAULT_TIMEOUT_MS) / 1000)} s.`);
      } else {
        console.error(`Check ${spec.id} failed:`, error);
        skip(`No answer from ${spec.source} (request failed).`);
      }
      return null;
    } finally {
      this.values.set(spec.id, value);
      // Sources the task didn't report itself count as finished now
      while (reported < planned) report(!spec.selfReport && answered);
      // Keyed sources skipped inside this task (e.g. OTX within blocklists) get a row too
      for (const skipped of this.ctx.keys.skipped()) {
        if (this.skippedServices.has(skipped.service)) continue;
        this.skippedServices.add(skipped.service);
        const name = getService(skipped.service)?.name ?? skipped.name;
        out.indicators.push(skippedIndicator(skipped.service, name, name, skipped.reason));
      }
      this.outputs.set(spec.id, out);
      this.ctx.progress.task(spec.id, state, out.indicators);
    }
  }
}
