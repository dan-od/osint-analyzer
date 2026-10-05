'use client';

import { useRef, useState, type DragEvent, type FormEvent } from 'react';
import { CornerTicks } from '@/components/decor';
import { FormMessage } from '@/components/auth/AuthCard';
import { BULK_MAX_TARGETS, minutesFreeOnly, minutesWithVirusTotal } from '@/lib/bulk-limits';
import type { BulkOptions, BulkParseResult } from '@/types/bulk';

interface BulkComposerProps {
  value: string;
  onChange: (value: string) => void;
  name: string;
  onFile: (file: File) => void;
  onSubmit: () => void;
  preview: BulkParseResult & { csv: boolean; column: string | null };
  options: BulkOptions;
  onOption: (key: keyof BulkOptions, value: boolean) => void;
  submitting: boolean;
  blockedReason: string | null;
  error: string | null;
}

export default function BulkComposer(props: BulkComposerProps) {
  const { value, onChange, name, onFile, onSubmit, preview, options, onOption, submitting, blockedReason, error } = props;
  const fileRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    onSubmit();
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) onFile(file);
  };

  const ignored = [
    preview.duplicates && `${preview.duplicates} duplicate${preview.duplicates === 1 ? '' : 's'}`,
    preview.internal.length && `${preview.internal.length} internal`,
    preview.unsupported.length && `${preview.unsupported.length} not IP or domain`,
    preview.invalid.length && `${preview.invalid.length} unrecognised`,
    preview.truncated && `${preview.truncated} over the ${BULK_MAX_TARGETS} limit`,
  ].filter(Boolean);

  const check = (key: keyof BulkOptions, label: string, hint?: string) => (
    <label className="flex cursor-pointer items-start gap-[10px]">
      <input
        type="checkbox"
        checked={options[key]}
        onChange={(e) => onOption(key, e.target.checked)}
        className="mt-[3px] h-4 w-4 flex-none accent-[#F28C28]"
      />
      <span>
        {label} {hint && <span className="text-muted">{hint}</span>}
      </span>
    </label>
  );

  return (
    <div className="oa-wrap relative flex flex-wrap items-start gap-x-12 gap-y-6 pb-8 pt-10">
      <div className="flex min-w-0 flex-[999_1_420px] flex-col gap-[10px]">
        <h1 className="oa-display text-[30px] leading-[1.1]">Bulk check</h1>
        <p className="m-0 max-w-[60ch] text-muted">
          Paste targets one per line, or drop the CSV you exported from FortiSIEM. Internal addresses and duplicates are removed
          before anything is looked up.
        </p>
        <form
          onSubmit={submit}
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={`relative mt-2 flex flex-col gap-[10px] rounded border border-dashed bg-panel p-[22px] ${dragging ? 'border-accent' : 'border-line-strong'}`}
        >
          <CornerTicks tone="accent" />
          <label htmlFor="list" className="oa-label">
            Targets{name !== 'Pasted list' && <span className="text-faint"> from {name}</span>}
          </label>
          <textarea
            id="list"
            rows={5}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            spellCheck={false}
            placeholder={'203.0.113.42\ncdn-assets-update.example\n203.0.113.77'}
            className="box-border w-full resize-y rounded border border-line-strong bg-ground px-3 py-[10px] font-mono text-[14px] text-ink"
          />
          {value.trim() && (
            <p className="m-0 text-[13px] text-muted">
              <span className="text-ink">{preview.targets.length}</span> unique target{preview.targets.length === 1 ? '' : 's'} to check
              {preview.csv && (preview.column ? `, from the "${preview.column}" column` : ', from the first column')}
              {ignored.length > 0 && `. Ignored: ${ignored.join(', ')}.`}
            </p>
          )}
          {error && <FormMessage>{error}</FormMessage>}
          {blockedReason && <p className="m-0 text-[13px] text-muted">{blockedReason}</p>}
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="submit"
              disabled={submitting || !!blockedReason || (preview.targets.length === 0 && preview.internal.length === 0)}
              className="oa-btn-primary h-10 px-[18px] text-[14px]"
            >
              {submitting ? 'Starting…' : 'Start job'}
            </button>
            <button type="button" onClick={() => fileRef.current?.click()} className="oa-btn">
              Upload CSV
            </button>
            <span className="text-[13px] text-muted">or drag a file here. A column named ip, domain, target or url is picked up.</span>
            <input
              ref={fileRef}
              type="file"
              accept=".csv,.txt,text/csv,text/plain"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) onFile(file);
                e.target.value = '';
              }}
            />
          </div>
        </form>
      </div>

      <div className="flex max-w-[360px] flex-[1_1_280px] flex-col gap-[10px] text-[14px]">
        <span className="text-[13px] text-muted">Options</span>
        {check('skipInternal', 'Skip private and reserved IPs', '(10/8, 172.16/12, 192.168/16, loopback, CGNAT)')}
        {check('reuseCache', 'Reuse results from the last 24 hours')}
        {check('freeSourcesOnly', 'Free sources only', '(saves your VirusTotal quota)')}
        <p className="m-0 mt-[6px] text-[13px] text-muted">
          Up to {BULK_MAX_TARGETS} targets per job, one running job per account. Rate limits are respected per key: 200 targets
          with VirusTotal on takes about {minutesWithVirusTotal(200)} minutes; without it, about {minutesFreeOnly(200)}.
        </p>
      </div>
    </div>
  );
}
