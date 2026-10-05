'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import CheckForm from '@/components/check/CheckForm';
import { MarkBleed } from '@/components/decor';
import { TYPE_LABEL } from '@/lib/verdict';
import type { AnalysisType } from '@/types';

export interface DashboardData {
  firstName: string;
  recent: { target: string; type: AnalysisType; checkedAt: string }[];
  jobs: { id: string; name: string; total: number; flagged: number; status: string; createdAt: string }[];
  quotas: { name: string; period: string; used: number; limit: number }[];
  missing: { names: string[]; allFree: boolean; paid: string[] };
  feeds: { name: string; entries: number | null; updatedAt: string | null }[];
}

function greeting(): string {
  const h = new Date().getHours();
  return h < 5 ? 'Evening' : h < 12 ? 'Morning' : h < 18 ? 'Afternoon' : 'Evening';
}

function when(iso: string): string {
  const d = new Date(iso);
  const today = new Date();
  const yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);
  const time = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  if (d.toDateString() === today.toDateString()) return `Today, ${time}`;
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function ago(iso: string): string {
  const hours = Math.round((Date.now() - new Date(iso).getTime()) / 3_600_000);
  return hours < 1 ? 'just now' : hours < 48 ? `${hours}h ago` : `${Math.round(hours / 24)}d ago`;
}

/** Local time of the next UTC midnight, when daily quotas reset */
function resetTime(): string {
  const next = new Date();
  next.setUTCHours(24, 0, 0, 0);
  return next.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

type Row =
  | { kind: 'check'; at: string; target: string; type: AnalysisType }
  | { kind: 'job'; at: string; id: string; name: string; total: number; flagged: number; status: string };

export default function Dashboard({ data }: { data: DashboardData }) {
  // Time-of-day words and local times only make sense in the browser
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const rows: Row[] = [
    ...data.recent.map((r): Row => ({ kind: 'check', at: r.checkedAt, target: r.target, type: r.type })),
    ...data.jobs.map((j): Row => ({ kind: 'job', at: j.createdAt, ...j })),
  ]
    .sort((a, b) => b.at.localeCompare(a.at))
    .slice(0, 12);

  return (
    <>
      <section aria-label="Top" className="oa-dots relative overflow-hidden border-b border-line">
        <MarkBleed size={340} style={{ right: -60, top: -90 }} />
        <div className="oa-wrap relative flex flex-col gap-4 pb-9 pt-10">
          <h1 className="oa-display text-[30px] leading-[1.1]">
            {mounted ? greeting() : 'Hello'}, {data.firstName}. What are we checking?
          </h1>
          <CheckForm variant="dashboard" />
        </div>
      </section>

      <div className="oa-wrap flex flex-wrap items-start gap-6 pb-12 pt-7">
        <main className="flex min-w-0 flex-[999_1_560px] flex-col gap-4">
          <div className="flex flex-wrap items-baseline gap-x-4 gap-y-2">
            <h2 className="m-0 text-[18px] font-semibold">Recent checks</h2>
            <span className="text-[14px] text-muted">Your last 7 days. Targets only, no results are kept.</span>
          </div>
          {rows.length === 0 ? (
            <p className="m-0 rounded border border-line px-[14px] py-4 text-[14px] text-muted">
              Nothing yet. Checks you run while logged in show up here for 7 days.
            </p>
          ) : (
            <div className="oa-tablewrap">
              <table className="oa-table oa-stack min-w-[620px]">
                <thead>
                  <tr>
                    <th scope="col">Target</th>
                    <th scope="col" className="w-[170px]">Kind</th>
                    <th scope="col" className="w-[140px]">When</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) =>
                    row.kind === 'check' ? (
                      <tr key={`c-${row.target}`} className="oa-row">
                        <td className="!py-[11px]">
                          <Link href={`/results?q=${encodeURIComponent(row.target)}`} className="break-all font-mono text-ink no-underline hover:text-ink hover:underline">
                            {row.target}
                          </Link>
                        </td>
                        <td className="!py-[11px] text-muted">{TYPE_LABEL[row.type]}</td>
                        <td className="!py-[11px] text-muted">{mounted ? when(row.at) : ''}</td>
                      </tr>
                    ) : (
                      <tr key={`j-${row.id}`} className="oa-row">
                        <td className="!py-[11px]">
                          <Link href={`/bulk?job=${row.id}`} className="text-ink no-underline hover:text-ink hover:underline">
                            Bulk job: {row.name}, {row.total} targets
                          </Link>
                        </td>
                        <td className="!py-[11px] text-muted">
                          {row.status === 'done' || row.status === 'cancelled' ? `${row.flagged} flagged` : `${row.status}, ${row.flagged} flagged`}
                        </td>
                        <td className="!py-[11px] text-muted">{mounted ? when(row.at) : ''}</td>
                      </tr>
                    )
                  )}
                </tbody>
              </table>
            </div>
          )}
        </main>

        <aside className="flex min-w-0 max-w-[360px] flex-[1_1_300px] flex-col gap-4">
          <section aria-label="Your quotas" className="flex flex-col gap-3 rounded border border-line p-4">
            <div className="flex items-baseline justify-between">
              <h2 className="m-0 text-[15px] font-semibold">Your quotas today</h2>
              <span className="text-[12px] text-muted">{mounted ? `resets ${resetTime()}` : ''}</span>
            </div>
            {data.quotas.length === 0 && (
              <p className="m-0 text-[13px] text-muted">
                No keys with free-tier limits yet. <Link href="/settings">Add keys in Settings</Link>.
              </p>
            )}
            {data.quotas.map((q) => {
              const pct = q.limit ? Math.min(100, Math.round((q.used / q.limit) * 100)) : 0;
              const tone = pct >= 100 ? 'text-fail-ink' : pct >= 80 ? 'text-warn' : 'text-muted';
              const bar = pct >= 100 ? 'bg-fail' : pct >= 80 ? 'bg-warn' : 'bg-ink';
              return (
                <div key={q.name} className="flex flex-col gap-[5px] text-[13px]">
                  <div className="flex justify-between gap-3">
                    <span>
                      {q.name} {q.period && <span className="text-faint">{q.period}</span>}
                    </span>
                    <span className={`font-mono ${tone}`}>
                      {q.used} / {q.limit}
                    </span>
                  </div>
                  <div className="h-1 overflow-hidden rounded-[2px] bg-line">
                    <div className={`h-full ${bar}`} style={{ width: `${Math.max(pct, q.used > 0 ? 2 : 0)}%` }} />
                  </div>
                </div>
              );
            })}
          </section>

          {data.missing.names.length > 0 && (
            <section aria-label="Missing keys" className="flex flex-col gap-2 rounded border border-line-strong bg-panel p-4">
              <h2 className="m-0 text-[15px] font-semibold">
                {data.missing.names.length} source{data.missing.names.length === 1 ? ' is' : 's are'} off for you
              </h2>
              <p className="m-0 text-[14px] text-muted">
                {listNames(data.missing.names)} {data.missing.names.length === 1 ? 'is' : 'are'} skipped until you add keys.{' '}
                {data.missing.allFree
                  ? data.missing.names.length === 2 ? 'Both are free.' : data.missing.names.length === 1 ? 'It is free.' : 'All are free.'
                  : `All but ${listNames(data.missing.paid)} are free.`}
              </p>
              <Link href="/settings" className="text-[14px]">
                Add {data.missing.names.length === 1 ? 'it' : 'them'} in Settings
              </Link>
            </section>
          )}

          <section aria-label="Feeds" className="flex flex-col gap-2 rounded border border-line p-4 text-[13px] text-muted">
            <h2 className="m-0 text-[15px] font-semibold text-ink">Local feeds</h2>
            {data.feeds.map((f) => (
              <div key={f.name} className="flex justify-between gap-3">
                <span>{f.name}</span>
                <span className="font-mono">
                  {f.entries !== null && f.updatedAt ? `${f.entries.toLocaleString('en-US')} · ${mounted ? ago(f.updatedAt) : ''}` : 'not downloaded yet'}
                </span>
              </div>
            ))}
          </section>
        </aside>
      </div>
    </>
  );
}

function listNames(names: string[]): string {
  if (names.length <= 1) return names.join('');
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}
