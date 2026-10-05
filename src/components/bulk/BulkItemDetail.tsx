'use client';

import Link from 'next/link';
import BlocklistCoverageCard from '@/components/blocklist/BlocklistCoverageCard';
import PivotLinks from '@/components/blocklist/PivotLinks';
import { FindingsTable } from '@/components/results-page/Findings';
import { levelWord, toneForLevel } from '@/lib/verdict';
import type { AnalysisResult } from '@/types';

/** Row detail under the bulk table: verdict, blocklist coverage, pivots, findings */
export default function BulkItemDetail({
  result,
  error,
  jobId,
  idx,
  onClose,
}: {
  result: AnalysisResult | null;
  error: string | null;
  jobId: string;
  idx: number;
  onClose: () => void;
}) {
  if (error) return <div className="oa-wrap pb-12"><p className="m-0 text-ink">{error}</p></div>;
  if (!result) return <div className="oa-wrap pb-12"><p className="m-0 text-muted">Loading result…</p></div>;
  const tone = toneForLevel(result.riskLevel);

  return (
    <section aria-label={`Detail for ${result.query}`} className="oa-wrap flex flex-col gap-5 pb-12">
      <div className="flex flex-col gap-3 rounded border border-line bg-panel p-5">
        <div className="flex flex-wrap items-center gap-[10px]">
          <span className={`oa-badge ${tone}`}>
            <span className={`oa-dot ${tone}`} />
            {levelWord(result.riskLevel)} risk
          </span>
          <span className="font-mono text-[14px] text-muted">{result.riskScore} / 100</span>
          <button type="button" onClick={onClose} className="ml-auto cursor-pointer border-0 bg-transparent p-0 text-[13px] text-muted hover:text-ink">
            Close
          </button>
        </div>
        <h3 className="m-0 break-all font-mono text-[22px] font-medium text-ink-strong">{result.query}</h3>
        <p className="m-0 text-ink-body">{result.summary}</p>
        <div className="flex flex-wrap gap-2">
          <PivotLinks pivots={result.pivots ?? []} />
          <Link href={`/results?q=${encodeURIComponent(result.query)}&job=${jobId}&item=${idx}`} className="oa-btn h-9 px-3 text-[13px]">
            Full result
          </Link>
        </div>
      </div>
      {result.blocklist && <BlocklistCoverageCard coverage={result.blocklist} />}
      <FindingsTable rows={result.indicators.map((indicator, i) => ({ kind: 'finding', key: `${indicator.id}-${i}`, indicator }))} />
    </section>
  );
}
