'use client';

import type { FormEvent, ReactNode } from 'react';
import { ConvergeMark } from '@/components/brand/Logo';
import { CornerTicks, DataColumn, SOURCE_LINES } from '@/components/decor';
import { levelWord, toneForLevel, TONE_INK, TYPE_LABEL, TYPE_SHORT } from '@/lib/verdict';
import type { AnalysisResult, AnalysisType } from '@/types';

/* ---------------------------------------------------------------- search */

export function SearchBar({
  value,
  onChange,
  onSubmit,
  detected,
  action,
}: {
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  detected: AnalysisType | null;
  action: { label: string; kind: 'primary' | 'cancel'; onClick?: () => void };
}) {
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (action.kind === 'cancel') action.onClick?.();
    else onSubmit();
  };
  return (
    <div className="border-b border-line bg-panel">
      <form onSubmit={submit} className="oa-wrap flex flex-wrap items-center gap-[10px] py-[14px]">
        <label htmlFor="q" className="oa-sr">Target to check</label>
        <input
          id="q"
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete="off"
          spellCheck={false}
          placeholder="IP, domain, email, phone or wallet"
          aria-describedby="q-detected"
          className="oa-input oa-mono flex-[999_1_320px] px-[14px]"
        />
        <div className="flex flex-auto gap-2">
          <span id="q-detected" className="inline-flex h-11 items-center rounded border border-line-strong px-3 text-[13px] text-muted whitespace-nowrap">
            {detected ? `Detected: ${TYPE_SHORT[detected]}` : 'Type not recognised'}
          </span>
          {action.kind === 'cancel' ? (
            <button type="submit" className="oa-btn h-11 px-5 text-[15px] font-semibold text-muted">
              {action.label}
            </button>
          ) : (
            <button type="submit" className="oa-btn-primary" disabled={!value.trim()}>
              {action.label}
            </button>
          )}
        </div>
      </form>
    </div>
  );
}

/* ---------------------------------------------------------- score panel */

function ScorePanel({ children }: { children: ReactNode }) {
  return (
    <dl className="relative m-0 box-border grid max-w-[420px] max-[720px]:max-w-none flex-[1_1_300px] grid-cols-2 gap-x-8 gap-y-[14px] rounded border border-line bg-[rgba(21,24,28,0.7)] px-5 py-[18px]">
      <CornerTicks />
      {children}
    </dl>
  );
}

function Stat({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-[2px]">
      <dt className="text-[13px] text-muted">{label}</dt>
      {children}
    </div>
  );
}

const big = 'm-0 font-mono text-[28px] leading-[1.1]';
const mid = 'm-0 font-mono text-[20px] leading-[1.2] text-ink';
const unit = 'text-[14px] text-muted';

/* ------------------------------------------------------- final verdict */

export function VerdictBand({
  result,
  actions,
  note,
}: {
  result: AnalysisResult;
  actions: ReactNode;
  note?: ReactNode;
}) {
  const tone = toneForLevel(result.riskLevel);
  const internal = result.facts?.verdict === 'Internal IP – not checked';
  const checkedAt = new Date(result.timestamp);
  return (
    <section aria-label="Verdict" className="relative overflow-hidden border-b border-line bg-ground">
      <DataColumn lines={SOURCE_LINES} />
      <div className="oa-wrap relative flex flex-wrap items-start gap-x-12 gap-y-6 pb-6 pt-7">
        <div className="flex min-w-0 flex-[999_1_420px] flex-col gap-[10px]">
          <div className="flex flex-wrap items-center gap-[10px]">
            {internal ? (
              <span className="oa-badge pass" style={{ color: 'var(--skip)' }}>
                <span className="oa-dot skip" />
                Internal IP, not checked
              </span>
            ) : (
              <span className={`oa-badge ${tone}`}>
                <span className={`oa-dot ${tone}`} />
                {levelWord(result.riskLevel)} risk
              </span>
            )}
            <span className="text-[13px] text-muted">{TYPE_LABEL[result.type]}</span>
          </div>
          <h1 className="m-0 break-all font-mono text-[30px] font-medium leading-[1.15] text-ink-strong">{result.query}</h1>
          <p className="m-0 mt-[2px] max-w-[62ch] text-[16px] text-ink-body">{result.summary}</p>
          {note}
          <div className="mt-[6px] flex flex-wrap gap-2">{actions}</div>
        </div>
        <ScorePanel>
          <Stat label="Risk score">
            <dd className={`${big} ${internal ? 'text-faint' : TONE_INK[tone]}`}>
              {internal ? '–' : result.riskScore}
              <span className={unit}> / 100</span>
            </dd>
          </Stat>
          <Stat label="Confidence">
            <dd className={`${big} text-ink`}>
              {result.confidence}
              <span className={unit}> %</span>
            </dd>
          </Stat>
          <Stat label="Sources checked">
            <dd className={mid}>
              {result.sources?.answered ?? '–'}
              <span className={unit}> of {result.sources?.total ?? '–'}</span>
            </dd>
          </Stat>
          <Stat label="Checked">
            <dd className="m-0 text-[15px] leading-[1.3] text-ink">
              {checkedAt.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
              <br />
              <span className="text-muted">
                {checkedAt.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false, timeZoneName: 'short' })}
              </span>
            </dd>
          </Stat>
        </ScorePanel>
      </div>
    </section>
  );
}

/* ------------------------------------------------------- still checking */

export function CheckingBand({
  target,
  done,
  answered,
  total,
  flagged,
  elapsedMs,
}: {
  target: string;
  done: number;
  answered: number;
  total: number;
  flagged: number;
  elapsedMs: number;
}) {
  const percent = total ? Math.round((done / total) * 100) : 0;
  return (
    <section aria-label="Progress" className="oa-dots border-b border-line bg-ground">
      <div className="oa-wrap flex flex-wrap items-start gap-x-12 gap-y-5 pb-6 pt-7">
        <div className="flex min-w-0 flex-[999_1_420px] flex-col gap-[10px]">
          <div className="flex items-center gap-[14px]">
            <ConvergeMark size={52} />
            <span className="text-[13px] font-semibold text-muted">
              {total ? `Checking, ${done} of ${total} sources in` : 'Starting the check'}
            </span>
          </div>
          <h1 className="m-0 break-all font-mono text-[30px] font-medium leading-[1.15] text-ink-strong">{target}</h1>
          <p className="m-0 mt-[2px] text-[16px] text-ink-body">
            {total ? `${done} of ${total} sources have answered. ` : ''}
            {flagged === 0 ? 'Nothing flagged so far.' : `${flagged} finding${flagged === 1 ? '' : 's'} flagged so far.`} Rows fill in as each source
            replies; you can read the finished ones now.
          </p>
          <div
            role="progressbar"
            aria-label="Sources answered"
            aria-valuemin={0}
            aria-valuemax={total || 1}
            aria-valuenow={done}
            className="mt-[6px] h-1 max-w-[520px] overflow-hidden rounded-[2px] bg-line"
          >
            <div className="h-full bg-accent transition-[width] duration-300" style={{ width: `${percent}%` }} />
          </div>
        </div>
        <ScorePanel>
          <Stat label="Risk score">
            <dd className={`${big} text-faint`}>
              –<span className="text-[14px]"> / 100</span>
            </dd>
          </Stat>
          <Stat label="Elapsed">
            <dd className={`${big} text-ink`}>
              {(elapsedMs / 1000).toFixed(1)}
              <span className={unit}> s</span>
            </dd>
          </Stat>
          <Stat label="Sources answered">
            <dd className={mid}>
              {answered}
              <span className={unit}> of {total || '–'}</span>
            </dd>
          </Stat>
          <Stat label="Flagged so far">
            <dd className={`${mid} ${flagged > 0 ? 'text-fail-ink' : 'text-pass-ink'}`}>{flagged}</dd>
          </Stat>
        </ScorePanel>
      </div>
    </section>
  );
}
