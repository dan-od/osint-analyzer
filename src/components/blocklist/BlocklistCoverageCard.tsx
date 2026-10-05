'use client';

import { useState } from 'react';
import type { BlocklistCoverage, BlocklistSourceResult } from '@/types';

const STATUS: Record<BlocklistSourceResult['status'], { word: string; dot: string; ink: string }> = {
  listed: { word: 'Listed', dot: 'fail', ink: 'text-fail-ink font-semibold' },
  clean: { word: 'Clean', dot: 'pass', ink: 'text-pass-ink font-medium' },
  refused: { word: 'Refused', dot: 'skip', ink: 'text-skip' },
  error: { word: 'No answer', dot: 'skip', ink: 'text-skip' },
  skipped: { word: 'Skipped', dot: 'skip', ink: 'text-skip' },
};

const TRUST_WORD = { high: 'High', medium: 'Medium', low: 'Low', noisy: 'Noisy' };

/** "Flagged by 4/27 sources", with every source's answer one click away */
export default function BlocklistCoverageCard({ coverage }: { coverage: BlocklistCoverage }) {
  const [showAll, setShowAll] = useState(false);
  const listed = coverage.sources.filter((s) => s.status === 'listed');
  const visible = showAll ? coverage.sources : listed;
  const noAnswer = coverage.total - coverage.checked;

  return (
    <section aria-label="Blocklist coverage" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-2">
        <h2 className="m-0 text-[18px] font-semibold">Blocklist coverage</h2>
        <span className="text-[14px] text-muted">
          Flagged by{' '}
          <span className={`font-mono ${coverage.flagged > 0 ? 'text-fail-ink' : 'text-pass-ink'}`}>
            {coverage.flagged}/{coverage.checked}
          </span>{' '}
          sources, weighted score <span className="font-mono text-ink">{coverage.weightedScore}</span> / 100.
          {noAnswer > 0 && ` ${noAnswer} of ${coverage.total} gave no usable answer.`}
        </span>
      </div>
      {visible.length > 0 ? (
        <div className="oa-tablewrap">
          <table className="oa-table oa-stack min-w-[560px]">
            <thead>
              <tr>
                <th scope="col" className="w-[120px]">Result</th>
                <th scope="col" className="w-[190px]">List</th>
                <th scope="col">Detail</th>
                <th scope="col" className="w-[90px]">Trust</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((source) => {
                const st = STATUS[source.status];
                return (
                  <tr key={source.id} className={`oa-row ${source.status === 'listed' ? 'bg-fail-bg' : ''}`}>
                    <td className={`status ${st.ink}`}>
                      <span className={`oa-dot ${st.dot}`} />
                      {st.word}
                    </td>
                    <td className={source.status === 'listed' ? 'font-medium text-ink-strong' : 'text-ink'}>{source.name}</td>
                    <td className="text-muted">{source.detail ?? ''}</td>
                    <td className="src">{TRUST_WORD[source.trust]}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="m-0 text-[14px] text-muted">None of the {coverage.checked} lists that answered have it listed.</p>
      )}
      <div>
        <button type="button" onClick={() => setShowAll((v) => !v)} className="oa-btn h-9 px-3 text-[13px]">
          {showAll ? 'Show listings only' : `Show all ${coverage.total} sources`}
        </button>
      </div>
    </section>
  );
}
