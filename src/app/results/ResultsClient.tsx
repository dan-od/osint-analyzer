'use client';

import { Suspense, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { SearchBar, VerdictBand, CheckingBand } from '@/components/results-page/Verdict';
import { FindingsTable, findingsSummary, RawDataPanels, type FindingRow } from '@/components/results-page/Findings';
import { OpenIn, RecommendedAction, ScoreExplainer, SideColumn } from '@/components/results-page/Side';
import BlocklistCoverageCard from '@/components/blocklist/BlocklistCoverageCard';
import { useAnalysisStream } from '@/hooks/useAnalysisStream';
import { useCsvBasket } from '@/hooks/useCsvBasket';
import { decodeResult, shareUrl } from '@/lib/client/share';
import { fetchBulkItem } from '@/lib/client/bulk';
import { validateInput } from '@/lib/utils';
import type { AnalysisResult, Indicator } from '@/types';
import { levelWord } from '@/lib/verdict';

const STATUS_ORDER: Record<Indicator['status'], number> = { fail: 0, warning: 1, pass: 2, unknown: 3 };
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function sortRows(indicators: Indicator[]): Indicator[] {
  return [...indicators].sort(
    (a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );
}

export default function ResultsClient() {
  return (
    <Suspense fallback={null}>
      <Results />
    </Suspense>
  );
}

function Results() {
  const router = useRouter();
  const params = useSearchParams();
  const q = params.get('q') ?? '';
  const job = params.get('job');
  const item = params.get('item');

  const [input, setInput] = useState(q);
  const [origin, setOrigin] = useState<'live' | 'shared' | 'bulk'>('live');
  const { state, start, cancel, show, fail } = useAnalysisStream();
  const basket = useCsvBasket();
  const [now, setNow] = useState(Date.now());
  const [copied, setCopied] = useState(false);
  const loadedFor = useRef<string | null>(null);

  // Decide what to show: a shared result (#r=…), a stored bulk result, or a live check
  useEffect(() => {
    setInput(q);
    const key = `${q}|${job}|${item}|${window.location.hash}`;
    if (loadedFor.current === key) return;
    loadedFor.current = key;

    const hash = new URLSearchParams(window.location.hash.slice(1)).get('r');
    if (hash) {
      decodeResult(hash).then((result) => {
        if (result) {
          setOrigin('shared');
          show(result);
        } else {
          fail('This shared link is damaged or incomplete. Check the target again instead.');
        }
      });
    } else if (job && item) {
      fetchBulkItem(job, Number(item))
        .then((result) => {
          setOrigin('bulk');
          show(result);
        })
        .catch((err: Error) => fail(err.message || 'That bulk result is no longer available.'));
    } else if (q) {
      setOrigin('live');
      void start(q);
    }
  }, [q, job, item, start, show, fail]);

  // Elapsed counter while running
  useEffect(() => {
    if (state.phase !== 'running') return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 100);
    return () => clearInterval(timer);
  }, [state.phase]);

  const detected = useMemo(() => validateInput(input).type, [input]);

  const submit = () => {
    const value = input.trim();
    if (!value) return;
    if (value === q && !job && !window.location.hash) {
      loadedFor.current = null;
      setOrigin('live');
      void start(value);
    } else {
      router.push(`/results?q=${encodeURIComponent(value)}`);
    }
  };

  const running = state.phase === 'running';
  const result = state.result;

  // Rows: finished checks (flagged first) above the ones still querying
  const rows: FindingRow[] = useMemo(() => {
    if (result) return result.indicators.map((indicator, i) => ({ kind: 'finding', key: `${indicator.id}-${i}`, indicator }));
    const finished = sortRows(state.tasks.flatMap((t) => t.indicators));
    const pending = state.tasks.filter((t) => t.state === 'running');
    return [
      ...finished.map((indicator, i): FindingRow => ({ kind: 'finding', key: `${indicator.id}-${i}`, indicator })),
      ...pending.map((t): FindingRow => ({ kind: 'pending', key: `pending-${t.plan.id}`, task: t.plan })),
    ];
  }, [result, state.tasks]);

  const flaggedSoFar = rows.filter((r) => r.kind === 'finding' && (r.indicator.status === 'fail' || r.indicator.status === 'warning')).length;
  const announcement = useProgressAnnouncement(running, state.target ?? q, state.done, state.totalSources, flaggedSoFar, result);

  const copyLink = async (r: AnalysisResult) => {
    const url = await shareUrl(r);
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      window.prompt('Copy this link', url);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const exportJson = (r: AnalysisResult) => {
    const blob = new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `osint-${r.query.replace(/[^a-z0-9.@-]+/gi, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const searchAction = running
    ? { label: 'Cancel', kind: 'cancel' as const, onClick: cancel }
    : { label: result && input.trim() === result.query ? 'Check again' : 'Check', kind: 'primary' as const };

  return (
    <>
      {/* Screen readers hear the start, each quarter of the sources, and the verdict; not every row */}
      <p className="oa-sr" role="status" aria-live="polite" aria-atomic="true">
        {announcement}
      </p>
      <SearchBar value={input} onChange={setInput} onSubmit={submit} detected={detected} action={searchAction} />

      {state.phase === 'idle' && !q && <EmptyState />}

      {state.phase === 'error' && state.error && <ErrorBand message={state.error.message} status={state.error.status} target={q} />}

      {running && (
        <CheckingBand
          target={state.target ?? q}
          done={state.done}
          answered={state.answered}
          total={state.totalSources}
          flagged={flaggedSoFar}
          elapsedMs={Math.max(0, now - (state.startedAt ?? now))}
        />
      )}

      {result && (
        <VerdictBand
          result={result}
          note={
            origin !== 'live' && (
              <p className="m-0 text-[13px] text-muted">
                {origin === 'shared' ? 'Shared result' : 'From a bulk job'}, checked{' '}
                {new Date(result.timestamp).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' })}. Check again for fresh data.
              </p>
            )
          }
          actions={
            <>
              <button type="button" className="oa-btn" onClick={() => copyLink(result)}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1" />
                  <path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1" />
                </svg>
                {copied ? 'Link copied' : 'Copy link'}
              </button>
              <button type="button" className="oa-btn" onClick={() => exportJson(result)}>
                Export JSON
              </button>
              <button type="button" className="oa-btn" onClick={() => basket.add(result)}>
                {basket.has(result.query) ? 'Added to CSV' : 'Add to CSV'}
              </button>
              {basket.count > 0 && (
                <button type="button" className="oa-btn" onClick={basket.download}>
                  Download CSV ({basket.count})
                </button>
              )}
            </>
          }
        />
      )}

      {(running || result) && (
        <div className="oa-wrap flex flex-wrap items-start gap-6 pb-12 pt-6">
          <div className="flex min-w-0 flex-[999_1_560px] flex-col gap-5">
            <div className="flex flex-wrap items-baseline gap-x-4 gap-y-2">
              <h2 className="m-0 text-[18px] font-semibold">Findings</h2>
              <span className="text-[14px] text-muted">
                {result ? findingsSummary(result.indicators) : 'Flagged results jump to the top as they arrive.'}
              </span>
            </div>
            <FindingsTable rows={rows} />

            {result?.blocklist && (
              <div className="mt-3">
                <BlocklistCoverageCard coverage={result.blocklist} />
              </div>
            )}

            {result && Object.keys(result.details).length > 0 && (
              <>
                <h2 className="m-0 mt-3 text-[18px] font-semibold">Raw data</h2>
                <RawDataPanels details={result.details} />
              </>
            )}
          </div>

          <SideColumn>
            {result && <RecommendedAction items={result.recommendations} />}
            <OpenIn pivots={result?.pivots ?? state.pivots} early={running} />
            {result && <ScoreExplainer />}
          </SideColumn>
        </div>
      )}
    </>
  );
}

function EmptyState() {
  return (
    <section className="oa-dots border-b border-line">
      <div className="oa-wrap flex flex-col gap-2 py-12">
        <h1 className="oa-display text-[30px] leading-[1.1]">What are we checking?</h1>
        <p className="m-0 text-muted">Paste an IP, domain, email, phone number or wallet in the box above.</p>
      </div>
    </section>
  );
}

function ErrorBand({ message, status, target }: { message: string; status?: number; target: string }) {
  return (
    <section aria-label="Problem" className="oa-dots border-b border-line">
      <div className="oa-wrap flex flex-col gap-3 py-10">
        {target && <h1 className="m-0 break-all font-mono text-[30px] font-medium leading-[1.15] text-ink-strong">{target}</h1>}
        <p className="m-0 max-w-[62ch] text-[16px] text-ink-body">{message}</p>
        {status === 401 && (
          <div>
            <Link href={`/login?next=${encodeURIComponent(`/results?q=${encodeURIComponent(target)}`)}`} className="oa-btn-primary">
              Log in
            </Link>
          </div>
        )}
      </div>
    </section>
  );
}

/** Polite progress messages: start, 25/50/75 %, and the finished verdict */
function useProgressAnnouncement(
  running: boolean,
  target: string,
  done: number,
  total: number,
  flagged: number,
  result: AnalysisResult | null | undefined
): string {
  const [message, setMessage] = useState('');
  const quarter = useRef(-1);
  const quarterNow = total ? Math.min(3, Math.floor((done / total) * 4)) : 0;

  useEffect(() => {
    if (running) {
      if (quarter.current === -1) setMessage(`Checking ${target}. Results appear as each source answers.`);
      else if (quarterNow > quarter.current && quarterNow > 0) {
        setMessage(`${done} of ${total} sources have answered. ${flagged === 0 ? 'Nothing flagged so far.' : `${flagged} flagged so far.`}`);
      }
      quarter.current = Math.max(quarter.current, quarterNow);
      return;
    }
    quarter.current = -1;
    if (result) {
      const findings = result.indicators.filter((i) => i.status === 'fail' || i.status === 'warning').length;
      setMessage(
        `Check finished. ${levelWord(result.riskLevel)} risk, score ${result.riskScore} out of 100. ${findings} finding${findings === 1 ? '' : 's'} flagged.`
      );
    }
  }, [running, target, done, total, flagged, result, quarterNow]);

  return message;
}
