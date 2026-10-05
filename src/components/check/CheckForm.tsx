'use client';

import { useRef, useState, type ClipboardEvent, type FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import { parseBulkInput } from '@/lib/bulk-input';
import { stashBulkInput } from '@/lib/client/bulk-handoff';

/**
 * The main search box. On the dashboard, pasting several targets (or
 * uploading a CSV) hands them to the bulk page instead.
 */
export default function CheckForm({ variant }: { variant: 'home' | 'dashboard' }) {
  const router = useRouter();
  const [value, setValue] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const q = value.trim();
    if (q) router.push(`/results?q=${encodeURIComponent(q)}`);
  };

  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    if (variant !== 'dashboard') return;
    const text = e.clipboardData.getData('text');
    if (/[\r\n]/.test(text.trim()) && parseBulkInput(text).targets.length > 1) {
      e.preventDefault();
      stashBulkInput({ text, name: 'Pasted list' });
      router.push('/bulk');
    }
  };

  const onFile = async (file: File) => {
    stashBulkInput({ text: await file.text(), name: file.name });
    router.push('/bulk');
  };

  if (variant === 'home') {
    return (
      <form onSubmit={submit} className="mt-1 flex max-w-[700px] flex-wrap gap-[10px]">
        <label htmlFor="q" className="oa-sr">What to check</label>
        <input
          id="q"
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          autoComplete="off"
          spellCheck={false}
          placeholder="a website, email, phone number, IP or wallet"
          className="oa-input oa-mono h-14 flex-[999_1_320px] bg-panel px-[18px] text-[16px]"
        />
        <button type="submit" className="oa-btn-primary h-14 max-w-[170px] flex-auto px-[26px] text-[16px]">
          Check it
        </button>
      </form>
    );
  }

  return (
    <form onSubmit={submit} className="flex max-w-[820px] flex-wrap gap-[10px]">
      <label htmlFor="q" className="oa-sr">Target to check</label>
      <input
        id="q"
        type="text"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onPaste={onPaste}
        autoComplete="off"
        spellCheck={false}
        placeholder="IP, domain, email, phone or wallet. Paste several, one per line, to start a bulk job."
        className="oa-input oa-mono h-[52px] flex-[999_1_360px] bg-panel px-4"
      />
      <button type="submit" className="oa-btn-primary h-[52px] max-w-[140px] flex-auto px-6 text-[16px]">
        Check
      </button>
      <button type="button" onClick={() => fileRef.current?.click()} className="oa-btn h-[52px] bg-transparent px-[18px] text-[15px] font-medium">
        Upload CSV
      </button>
      <input
        ref={fileRef}
        type="file"
        accept=".csv,.txt,text/csv,text/plain"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) void onFile(file);
          e.target.value = '';
        }}
      />
    </form>
  );
}
