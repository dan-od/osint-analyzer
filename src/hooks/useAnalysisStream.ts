'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type { AnalysisEvent, AnalysisResult, AnalysisType, Indicator, PivotLink, PlannedTask } from '@/types';

export interface TaskState {
  plan: PlannedTask;
  state: 'running' | 'done' | 'skipped';
  indicators: Indicator[];
}

export interface StreamState {
  phase: 'idle' | 'running' | 'done' | 'error';
  target: string | null;
  kind: AnalysisType | null;
  tasks: TaskState[];
  pivots: PivotLink[];
  totalSources: number;
  done: number;
  answered: number;
  startedAt: number | null;
  result: AnalysisResult | null;
  error: { message: string; status?: number } | null;
}

const IDLE: StreamState = {
  phase: 'idle',
  target: null,
  kind: null,
  tasks: [],
  pivots: [],
  totalSources: 0,
  done: 0,
  answered: 0,
  startedAt: null,
  result: null,
  error: null,
};

function reduce(state: StreamState, event: AnalysisEvent): StreamState {
  switch (event.type) {
    case 'plan':
      return {
        ...state,
        target: event.target,
        kind: event.kind,
        pivots: event.pivots,
        totalSources: event.totalSources,
        tasks: event.tasks.map((plan) => ({ plan, state: 'running', indicators: [] })),
      };
    case 'progress':
      return { ...state, done: event.done, answered: event.answered };
    case 'task':
      return {
        ...state,
        done: event.done,
        answered: event.answered,
        tasks: state.tasks.map((t) => (t.plan.id === event.id ? { ...t, state: event.state, indicators: event.indicators } : t)),
      };
    case 'result':
      return { ...state, phase: 'done', result: event.result, target: event.result.query, kind: event.result.type };
    case 'error':
      return { ...state, phase: 'error', error: { message: event.error, status: event.status } };
  }
}

/** Runs one check against /api/analyze/stream and exposes its live state. */
export function useAnalysisStream() {
  const [state, setState] = useState<StreamState>(IDLE);
  const abortRef = useRef<AbortController | null>(null);

  const cancel = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setState((s) => (s.phase === 'running' ? { ...s, phase: 'error', error: { message: 'Check cancelled.' } } : s));
  }, []);

  const start = useCallback(async (query: string) => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setState({ ...IDLE, phase: 'running', target: query, startedAt: Date.now() });

    try {
      const response = await fetch('/api/analyze/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
        signal: controller.signal,
      });
      if (!response.ok || !response.body) {
        const payload = await response.json().catch(() => null);
        setState((s) => ({ ...s, phase: 'error', error: { message: payload?.error || 'The check failed.', status: response.status } }));
        return;
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let newline: number;
        while ((newline = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, newline).trim();
          buffer = buffer.slice(newline + 1);
          if (!line) continue;
          const event = JSON.parse(line) as AnalysisEvent;
          setState((s) => reduce(s, event));
        }
      }
      setState((s) => (s.phase === 'running' ? { ...s, phase: 'error', error: { message: 'The connection closed before the check finished.' } } : s));
    } catch (error) {
      if ((error as Error).name === 'AbortError') return;
      setState((s) => ({ ...s, phase: 'error', error: { message: 'Could not reach the server. Check your connection and try again.' } }));
    }
  }, []);

  /** Show a result that didn't come from a live check (shared link, bulk job) */
  const show = useCallback((result: AnalysisResult) => {
    abortRef.current?.abort();
    setState({ ...IDLE, phase: 'done', result, target: result.query, kind: result.type, pivots: result.pivots ?? [] });
  }, []);

  const fail = useCallback((message: string) => {
    setState({ ...IDLE, phase: 'error', error: { message } });
  }, []);

  useEffect(() => () => abortRef.current?.abort(), []);

  return { state, start, cancel, show, fail };
}
