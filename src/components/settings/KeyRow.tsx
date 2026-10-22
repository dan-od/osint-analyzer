'use client';

import { useState, type FormEvent } from 'react';
import type { ServiceInfo } from '@/lib/services';
import type { ApiKeyStatus } from '@/types/account';

export const KEY_GRID = 'grid grid-cols-[minmax(0,1.2fr)_minmax(0,1.6fr)_140px_220px] gap-4';

interface KeyRowProps {
  service: ServiceInfo;
  status: ApiKeyStatus;
  pending: boolean;
  error: string | null;
  disabled: boolean;
  onSave: (key: string) => Promise<boolean>;
  onDelete: () => Promise<boolean>;
}

function usageLine(status: ApiKeyStatus): string | null {
  const q = status.usage.quota;
  if (status.maskedKey && q) {
    if (q.dailyCap) return `${q.dailyCap.remaining} left today, ${q.remaining} this month`;
    const period = { day: 'today', week: 'this week', month: 'this month' }[q.period];
    return `${q.remaining.toLocaleString('en-US')} left ${period}`;
  }
  if (status.maskedKey) return status.usage.userToday ? `${status.usage.userToday} used today` : null;
  if (status.serverFallback) return 'Server key as fallback';
  return null;
}

export default function KeyRow({ service, status, pending, error, disabled, onSave, onDelete }: KeyRowProps) {
  const [value, setValue] = useState('');

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (await onSave(value)) setValue('');
  };

  const remove = async () => {
    if (window.confirm(`Delete your ${service.name} key?`)) await onDelete();
  };

  const usage = usageLine(status);

  return (
    <div className={`oa-g1 ${KEY_GRID} items-center border-b border-line py-4`}>
      <div className="flex min-w-0 flex-col gap-[3px]">
        <span className="font-semibold">{service.name}</span>
        <span className="text-[13px] text-muted">{service.description}</span>
      </div>
      <div className="min-w-0 text-[13px] text-muted">
        {service.freeTier}
        <div className="mt-[6px] flex gap-[14px]">
          <a href={service.signupUrl} target="_blank" rel="noopener noreferrer">Sign up</a>
          <a href={service.apiKeyUrl} target="_blank" rel="noopener noreferrer">Get your key</a>
        </div>
      </div>
      <div className="flex min-w-0 flex-col gap-1">
        {status.maskedKey ? (
          <span className="flex flex-wrap items-baseline gap-x-3">
            <span className="font-mono text-[13px] text-ink">{status.maskedKey}</span>
            <button
              type="button"
              onClick={remove}
              disabled={pending}
              aria-label={`Delete ${service.name} key`}
              className="border-0 bg-transparent p-0 text-[13px] text-link underline underline-offset-2 cursor-pointer hover:text-[#B9D3FA]"
            >
              Delete
            </button>
          </span>
        ) : (
          <span className="text-[13px] text-muted">
            <span className="oa-dot skip" />
            Not set
          </span>
        )}
        {usage && <span className="text-[12px] text-faint">{usage}</span>}
      </div>
      <form onSubmit={submit} className="flex min-w-0 flex-col gap-1">
        <div className="flex gap-2">
          <label htmlFor={`key-${service.id}`} className="oa-sr">
            {service.name} API key
          </label>
          <input
            id={`key-${service.id}`}
            type="password"
            autoComplete="off"
            spellCheck={false}
            placeholder={status.maskedKey ? 'Paste new key' : 'Paste key'}
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? `key-${service.id}-error` : undefined}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            disabled={disabled}
            className="oa-input oa-mono h-9 min-w-0 flex-[1_1_0] px-[10px] text-[13px]"
          />
          <button type="submit" disabled={pending || disabled || !value.trim()} className="oa-btn h-9 px-3 text-[13px]">
            {pending ? 'Saving' : 'Save'}
          </button>
        </div>
        {error && (
          <span id={`key-${service.id}-error`} role="alert" className="text-[12px] text-ink">
            {error}
          </span>
        )}
      </form>
    </div>
  );
}
