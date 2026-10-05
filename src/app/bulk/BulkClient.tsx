'use client';

import BulkComposer from '@/components/bulk/BulkComposer';
import BulkJobView from '@/components/bulk/BulkJobView';
import BulkItemDetail from '@/components/bulk/BulkItemDetail';
import { MarkBleed } from '@/components/decor';
import { FormMessage } from '@/components/auth/AuthCard';
import { useBulk } from '@/hooks/useBulk';

export default function BulkClient({ initialJobId }: { initialJobId: string | null }) {
  const bulk = useBulk(initialJobId);
  const { input, selection, job } = bulk;
  const earlier = bulk.jobs.filter((j) => j.id !== job?.id).slice(0, 5);

  return (
    <>
      <section aria-label="Top" className="oa-dots relative overflow-hidden border-b border-line">
        <MarkBleed size={340} style={{ right: -60, top: -90 }} />
        <BulkComposer
          value={input.value}
          onChange={input.setValue}
          name={input.name}
          onFile={(file) => void input.loadFile(file)}
          onSubmit={() => void input.start()}
          preview={input.preview}
          options={input.options}
          onOption={input.setOption}
          submitting={input.submitting}
          blockedReason={bulk.jobBusy ? 'A job is still running. Start another when it finishes, or cancel it.' : null}
          error={input.submitError}
        />
      </section>

      {bulk.jobError && (
        <div className="oa-wrap pt-6">
          <FormMessage>{bulk.jobError}</FormMessage>
        </div>
      )}

      {job ? (
        <BulkJobView
          job={job}
          items={bulk.items}
          filter={bulk.filter}
          onFilter={bulk.setFilter}
          sort={bulk.sort}
          onSort={bulk.toggleSort}
          selectedIdx={selection.idx}
          onSelect={selection.select}
          onPause={() => void bulk.pause()}
          onResume={() => void bulk.resume()}
          onCancel={() => void bulk.cancel()}
          exportUrl={bulk.exportUrl}
        />
      ) : (
        <div className="oa-wrap py-7">
          <p className="m-0 text-muted">Your job will show up here, with results filling in as each target finishes.</p>
        </div>
      )}

      {job && selection.idx !== null && (
        <BulkItemDetail result={selection.result} error={selection.error} jobId={job.id} idx={selection.idx} onClose={() => selection.select(null)} />
      )}

      {earlier.length > 0 && (
        <div className="oa-wrap pb-12 text-[13px] text-muted">
          Earlier jobs (kept 7 days):{' '}
          {earlier.map((j, i) => (
            <span key={j.id}>
              {i > 0 && ' · '}
              <button type="button" onClick={() => bulk.openJob(j.id)} className="cursor-pointer border-0 bg-transparent p-0 text-link hover:text-[#B9D3FA]">
                {j.name} ({new Date(j.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}, {j.flagged} flagged)
              </button>
            </span>
          ))}
        </div>
      )}
    </>
  );
}
