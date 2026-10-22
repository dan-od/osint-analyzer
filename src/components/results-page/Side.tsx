import type { ReactNode } from 'react';
import { SCORE_EXPLANATION } from '@/lib/score-explainer';
import type { PivotLink } from '@/types';
import { parseIp } from '@/lib/ip';

function Panel({ label, children, className = '' }: { label: string; children: ReactNode; className?: string }) {
  return (
    <section aria-label={label} className={`flex flex-col gap-[10px] rounded border border-line p-4 ${className}`}>
      {children}
    </section>
  );
}

export function SideColumn({ children }: { children: ReactNode }) {
  return <aside className="flex min-w-0 max-w-[360px] max-[720px]:max-w-none flex-[1_1_300px] flex-col gap-4">{children}</aside>;
}

export function RecommendedAction({ items }: { items: string[] }) {
  if (items.length === 0) return null;
  return (
    <Panel label="Recommended action">
      <h2 className="m-0 text-[15px] font-semibold">Recommended action</h2>
      <ol className="m-0 flex list-decimal flex-col gap-[6px] pl-[18px] text-[14px] text-ink-body">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ol>
    </Panel>
  );
}

export function OpenIn({ pivots, early }: { pivots: PivotLink[]; early?: boolean }) {
  if (pivots.length === 0) return null;
  return (
    <Panel label="Open in other tools">
      <h2 className="m-0 text-[15px] font-semibold">Open in</h2>
      {early && <p className="m-0 text-[13px] text-muted">These work before the check finishes.</p>}
      <div className="flex flex-col gap-[6px]">
        {pivots.map((p) => (
          <a
            key={p.label}
            href={p.url}
            target="_blank"
            rel="noopener noreferrer"
            className="box-border flex min-h-[44px] items-center justify-between gap-3 rounded border border-line px-3 py-[10px] text-ink no-underline hover:border-line-hover hover:text-ink"
          >
            <span>{p.label}</span>
            <span className={`min-w-0 truncate text-[13px] text-muted ${parseIp(p.target) ? 'font-mono' : ''}`}>
              {p.label === 'IPVoid' ? 'paste in form' : p.target}
            </span>
          </a>
        ))}
      </div>
    </Panel>
  );
}

export function ScoreExplainer() {
  return (
    <Panel label="How the score is calculated" className="!gap-2 text-[13px] text-muted">
      <h2 className="m-0 text-[15px] font-semibold text-ink">How this score works</h2>
      {SCORE_EXPLANATION.map((p) => (
        <p key={p} className="m-0">
          {p}
        </p>
      ))}
    </Panel>
  );
}
