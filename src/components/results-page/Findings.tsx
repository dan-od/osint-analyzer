'use client';

import Link from 'next/link';
import type { ReactNode } from 'react';
import { statusWord, toneForStatus } from '@/lib/verdict';
import type { AnalysisDetail, Indicator, PlannedTask } from '@/types';

export type FindingRow =
  | { kind: 'finding'; key: string; indicator: Indicator }
  | { kind: 'pending'; key: string; task: PlannedTask };

const PENDING_WIDTHS = [260, 180, 220, 150];

// Addresses and hostnames inside result text are data, so they're set in mono
const DATA_TOKEN = /(\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b)/gi;

function withMono(text: string): ReactNode[] {
  return text.split(DATA_TOKEN).map((part, i) =>
    i % 2 === 1 ? (
      <span key={i} className="font-mono text-[13px]">
        {part}
      </span>
    ) : (
      part
    )
  );
}

/** Skip reasons point at Settings / Log in; make those words links */
function withLinks(text: string): ReactNode[] {
  return text.split(/(Settings|[Ll]og in)/).map((part, i) => {
    if (part === 'Settings') return <Link key={i} href="/settings">Settings</Link>;
    if (/^[Ll]og in$/.test(part)) return <Link key={i} href="/login">{part}</Link>;
    return <span key={i}>{withMono(part)}</span>;
  });
}

const ROW_BG = { fail: 'bg-fail-bg', warn: 'bg-warn-bg', pass: '', skip: '' };
const STATUS_INK = { fail: 'text-fail-ink font-semibold', warn: 'text-warn font-semibold', pass: 'text-pass-ink font-medium', skip: 'text-skip font-normal' };
const NAME_INK = { fail: 'text-ink-strong font-medium', warn: 'text-ink-strong font-medium', pass: 'text-ink', skip: 'text-muted' };
const RESULT_INK = { fail: 'text-ink-body', warn: 'text-ink-body', pass: 'text-muted', skip: 'text-skip' };

export function FindingsTable({ rows }: { rows: FindingRow[] }) {
  return (
    <div className="oa-tablewrap">
      <table className="oa-table oa-stack min-w-[640px]">
        <thead>
          <tr>
            <th scope="col" className="w-[92px]">Status</th>
            <th scope="col" className="w-[180px]">Check</th>
            <th scope="col">Result</th>
            <th scope="col" className="w-[150px]">Source</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => {
            if (row.kind === 'pending') {
              return (
                <tr key={row.key} className="oa-row">
                  <td className="status text-skip !font-normal">
                    <span className="oa-dot busy" />
                    Querying
                  </td>
                  <td className="text-muted">{row.task.label}</td>
                  <td>
                    <span
                      className="inline-block h-[10px] max-w-full rounded-[2px] bg-raised align-middle"
                      style={{ width: PENDING_WIDTHS[i % PENDING_WIDTHS.length] }}
                    />
                  </td>
                  <td className="src !text-skip">{row.task.source}</td>
                </tr>
              );
            }
            const { indicator } = row;
            const tone = toneForStatus(indicator.status);
            return (
              <tr key={row.key} className={`oa-row ${ROW_BG[tone]}`}>
                <td className={`status ${STATUS_INK[tone]}`}>
                  <span className={`oa-dot ${tone}`} />
                  {statusWord(indicator.status)}
                </td>
                <td className={NAME_INK[tone]}>{indicator.name}</td>
                <td className={RESULT_INK[tone]}>{tone === 'skip' ? withLinks(indicator.description) : withMono(indicator.description)}</td>
                <td className={`src ${tone === 'skip' ? '!text-skip' : ''}`}>{indicator.source}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function findingsSummary(indicators: Indicator[]): string {
  const n = (status: Indicator['status']) => indicators.filter((i) => i.status === status).length;
  const parts = [
    `${n('fail')} failed`,
    `${n('warning')} warning${n('warning') === 1 ? '' : 's'}`,
    `${n('pass')} passed`,
    `${n('unknown')} skipped`,
  ];
  return `${parts.join(', ')}. Flagged first.`;
}

/* --------------------------------------------------------------- raw data */

function label(key: string): string {
  if (/^[A-Z]{2,}/.test(key) || key.includes(' ')) return key.charAt(0).toUpperCase() + key.slice(1);
  const spaced = key.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

function valueTone(value: unknown): string {
  const text = String(value ?? '').toLowerCase();
  if (text === 'missing' || text === 'none' || text === 'unknown') return text === 'missing' ? 'text-warn' : 'text-muted';
  return 'text-ink';
}

export function RawDataPanels({ details }: { details: Record<string, AnalysisDetail> }) {
  const entries = Object.entries(details);
  if (entries.length === 0) return null;
  return (
    <div className="oa-g1 grid grid-cols-2 gap-4">
      {entries.map(([key, detail]) => (
        <section key={key} aria-label={detail.title} className="flex min-w-0 flex-col gap-2 rounded border border-line px-4 py-[14px]">
          <h3 className="m-0 mb-1 text-[14px] font-semibold text-ink">{detail.title}</h3>
          {Object.entries(detail.data).map(([k, v]) => (
            <div key={k} className="flex justify-between gap-3 text-[13px]">
              <span className="shrink-0 text-muted">{label(k)}</span>
              <span className={`break-all text-right font-mono ${valueTone(v)}`}>{String(v ?? 'n/a')}</span>
            </div>
          ))}
        </section>
      ))}
    </div>
  );
}
