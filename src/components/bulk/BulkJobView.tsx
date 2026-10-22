'use client';

import Link from 'next/link';
import type { BulkFilter, ScoreSort } from '@/hooks/useBulk';
import { levelWord, toneForLevel, TONE_INK } from '@/lib/verdict';
import { VT_PER_MINUTE } from '@/lib/bulk-limits';
import type { BulkItemSummary, BulkJobDetail } from '@/types/bulk';

interface BulkJobViewProps {
  job: BulkJobDetail;
  items: BulkItemSummary[];
  filter: BulkFilter;
  onFilter: (f: BulkFilter) => void;
  sort: ScoreSort;
  onSort: () => void;
  selectedIdx: number | null;
  onSelect: (idx: number | null) => void;
  onPause: () => void;
  onResume: () => void;
  onCancel: () => void;
  exportUrl: string | null;
}

function statusLine(job: BulkJobDetail): { text: string; busy: boolean } {
  const done = job.completed;
  if (job.status === 'running' || job.status === 'queued') return { text: `Running, ${done} of ${job.total} done`, busy: true };
  if (job.status === 'paused') return { text: `Paused, ${done} of ${job.total} done`, busy: false };
  if (job.status === 'cancelled') return { text: `Cancelled, ${done} of ${job.total} done`, busy: false };
  return { text: `Finished, ${job.total} of ${job.total}`, busy: false };
}

export default function BulkJobView(props: BulkJobViewProps) {
  const { job, items, filter, onFilter, sort, onSort, selectedIdx, onSelect, onPause, onResume, onCancel, exportUrl } = props;
  const percent = job.total ? Math.round((job.completed / job.total) * 100) : 0;
  const status = statusLine(job);
  const running = job.status === 'running' || job.status === 'queued';
  const vtOn = !job.options.freeSourcesOnly;

  const chips: { key: BulkFilter; label: string; count: number }[] = [
    { key: 'flagged', label: 'Flagged', count: job.flagged },
    { key: 'clean', label: 'Clean', count: job.clean },
    { key: 'pending', label: 'Pending', count: job.pending },
    { key: 'errors', label: 'Errors', count: job.failed },
  ];

  return (
    <div className="oa-wrap flex flex-col gap-4 pb-12 pt-7">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-[10px]">
        <h2 className="m-0 break-all text-[18px] font-semibold">{job.name}</h2>
        <span className="inline-flex items-center gap-2 text-[13px] text-muted">
          <span className={`oa-dot !mr-0 ${status.busy ? 'busy' : 'skip'}`} />
          {status.text}
        </span>
        <span className="text-[13px] text-muted">
          {job.pasted} pasted{job.skipped > 0 && `, ${job.skipped} internal skipped`}
          {job.options.freeSourcesOnly && ', free sources only'}
        </span>
        <div className="ml-auto flex flex-wrap gap-2">
          {exportUrl && (
            <a href={exportUrl} className="oa-btn h-9 px-3 text-[13px]">
              {running || job.status === 'paused' ? 'Export CSV so far' : 'Export CSV'}
            </a>
          )}
          {running && (
            <button type="button" onClick={onPause} className="oa-btn h-9 px-3 text-[13px] text-muted">Pause</button>
          )}
          {job.status === 'paused' && (
            <button type="button" onClick={onResume} className="oa-btn h-9 px-3 text-[13px]">Resume</button>
          )}
          {(running || job.status === 'paused') && (
            <button type="button" onClick={onCancel} className="oa-btn h-9 px-3 text-[13px] text-muted">Cancel</button>
          )}
        </div>
      </div>

      <div className="h-1 overflow-hidden rounded-[2px] bg-line">
        <div className="h-full bg-accent transition-[width] duration-300" style={{ width: `${percent}%` }} />
      </div>

      <div className="flex flex-wrap gap-[6px] text-[13px]">
        {chips.map((c) => {
          const active = filter === c.key;
          return (
            <button
              key={c.key}
              type="button"
              aria-pressed={active}
              onClick={() => onFilter(c.key)}
              className={`cursor-pointer rounded border px-[10px] py-[6px] ${active ? 'border-line-strong bg-raised text-ink' : 'border-line bg-transparent text-muted'}`}
            >
              {c.label}, {c.count}
            </button>
          );
        })}
      </div>

      <div className="oa-tablewrap">
        <table aria-label="Bulk job targets" className="oa-table oa-stack min-w-[820px]">
          <thead>
            <tr>
              <th scope="col">Target</th>
              <th scope="col" className="w-[110px]">Verdict</th>
              <th scope="col" className="w-[70px]">
                <button type="button" onClick={onSort} className="cursor-pointer border-0 bg-transparent p-0 text-muted hover:text-ink" aria-label="Sort by score">
                  Score {sort === 'desc' ? '↓' : '↑'}
                </button>
              </th>
              <th scope="col" className="w-[110px]">Blocklists</th>
              <th scope="col">Top finding</th>
              <th scope="col" className="w-[90px]">Country</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && (
              <tr>
                <td colSpan={6} className="text-muted">Nothing in this view.</td>
              </tr>
            )}
            {items.map((item) => (
              <BulkRow
                key={item.idx}
                item={item}
                jobId={job.id}
                vtOn={vtOn}
                selected={selectedIdx === item.idx}
                onSelect={() => item.status === 'done' && onSelect(selectedIdx === item.idx ? null : item.idx)}
              />
            ))}
          </tbody>
        </table>
      </div>
      <p className="m-0 text-[13px] text-faint">Open a target for its full result, or click a finished row for blocklists and links.</p>
    </div>
  );
}

function BulkRow({
  item,
  jobId,
  vtOn,
  selected,
  onSelect,
}: {
  item: BulkItemSummary;
  jobId: string;
  vtOn: boolean;
  selected: boolean;
  onSelect: () => void;
}) {
  const td = '!py-[11px]';
  if (item.status !== 'done') {
    const pending = item.status === 'queued' || item.status === 'running';
    const word = { queued: 'Pending', running: 'Checking', error: 'Error', skipped: 'Skipped', cancelled: 'Cancelled', done: '' }[item.status];
    const note =
      item.status === 'skipped'
        ? 'Internal address, not looked up'
        : item.status === 'error'
          ? item.error ?? 'Failed'
          : item.status === 'cancelled'
            ? 'Job cancelled before this ran'
            : item.status === 'running' && vtOn
              ? `Waiting on VirusTotal (${VT_PER_MINUTE} a minute)`
              : 'In the queue';
    return (
      <tr className="oa-row">
        <td className={td}><span className="font-mono text-muted min-[721px]:whitespace-nowrap">{item.target}</span></td>
        <td className={`${td} whitespace-nowrap text-skip`}>
          <span className={`oa-dot ${pending ? 'busy' : 'skip'}`} />
          {word}
        </td>
        <td className={`${td} text-skip`}>–</td>
        <td className={`${td} text-skip`}>–</td>
        <td className={`${td} text-skip`}>{note}</td>
        <td className={`${td} text-skip`}>–</td>
      </tr>
    );
  }

  const level = item.riskLevel ?? 'low';
  const tone = toneForLevel(level);
  const f = item.facts;
  const hits = f?.blocklistHits ?? null;
  const flaggedHits = hits ? Number(hits.split('/')[0]) > 0 : false;
  const bg = tone === 'fail' ? 'bg-fail-bg' : tone === 'warn' ? 'bg-warn-bg' : '';
  return (
    <tr onClick={onSelect} className={`oa-row cursor-pointer ${bg} ${selected ? 'outline outline-1 -outline-offset-1 outline-line-hover' : ''}`}>
      <td className={td}>
        <Link
          href={`/results?q=${encodeURIComponent(item.target)}&job=${jobId}&item=${item.idx}`}
          onClick={(e) => e.stopPropagation()}
          className="font-mono text-ink-strong no-underline hover:text-ink-strong hover:underline min-[721px]:whitespace-nowrap"
        >
          {item.target}
        </Link>
        {item.cached && <span className="ml-2 text-[11px] text-faint">cached</span>}
      </td>
      <td className={`${td} whitespace-nowrap ${TONE_INK[tone]} ${tone === 'pass' ? 'font-medium' : 'font-semibold'}`}>
        <span className={`oa-dot ${tone}`} />
        {levelWord(level)}
      </td>
      <td className={`${td} font-mono`}>{item.riskScore}</td>
      <td className={`${td} font-mono ${flaggedHits ? 'text-fail-ink' : 'text-muted'}`}>{hits ? hits.replace('/', ' / ') : '–'}</td>
      <td className={`${td} text-ink-body`}>{f?.topFinding ?? (item.cached ? 'Cached result, nothing flagged' : 'Nothing flagged')}</td>
      <td className={`${td} text-muted`}>{f?.country ?? '–'}</td>
    </tr>
  );
}
