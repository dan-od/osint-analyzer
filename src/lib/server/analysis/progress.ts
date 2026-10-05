// Live progress for one analysis: which checks are planned, how many sources
// have answered, and each check's findings as soon as it finishes. The
// streaming API forwards these events to the results page; bulk jobs ignore them.
import type { AnalysisEvent, AnalysisType, Indicator, PivotLink, PlannedTask } from '@/types';

export type ProgressListener = (event: AnalysisEvent) => void;

export class Progress {
  totalSources = 0;
  /** Sources that finished, whatever the outcome */
  done = 0;
  /** Sources that gave a usable answer */
  answered = 0;
  private startedAt = Date.now();

  constructor(private listener?: ProgressListener) {}

  plan(target: string, kind: AnalysisType, tasks: PlannedTask[], pivots: PivotLink[]): void {
    this.totalSources = tasks.reduce((n, t) => n + t.sources, 0);
    this.listener?.({ type: 'plan', target, kind, tasks, totalSources: this.totalSources, pivots });
  }

  source(answered: boolean): void {
    this.done++;
    if (answered) this.answered++;
    this.listener?.({ type: 'progress', done: this.done, answered: this.answered });
  }

  task(id: string, state: 'done' | 'skipped', indicators: Indicator[]): void {
    this.listener?.({ type: 'task', id, state, indicators, done: this.done, answered: this.answered });
  }

  elapsedMs(): number {
    return Date.now() - this.startedAt;
  }
}
