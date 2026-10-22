'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { FormMessage } from '@/components/auth/AuthCard';
import { apiRequest } from '@/lib/client/http';
import { loginWith } from '@/lib/client/auth';

export interface SignInMethodsProps {
  hasPassword: boolean;
  /** Providers configured on this server */
  providers: { id: 'google' | 'github'; name: string }[];
  /** Providers linked to this account (may include one no longer configured) */
  linked: { provider: string; linkedAt: string }[];
}

const NAMES: Record<string, string> = { google: 'Google', github: 'GitHub' };

function dateLabel(iso: string): string {
  return new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
}

/** Password + Google + GitHub, each linkable/unlinkable; the last one can't be removed */
export default function SignInMethods({ hasPassword, providers, linked }: SignInMethodsProps) {
  const router = useRouter();
  const [pending, setPending] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const onlyOne = (hasPassword ? 1 : 0) + linked.length <= 1;
  const rows = [
    ...providers.map((p) => ({ id: p.id as string, name: p.name, configured: true })),
    ...linked
      .filter((l) => !providers.some((p) => p.id === l.provider))
      .map((l) => ({ id: l.provider, name: NAMES[l.provider] ?? l.provider, configured: false })),
  ];

  const remove = async (id: string, url: string) => {
    setPending(id);
    setMessage(null);
    try {
      await apiRequest(url, { method: 'DELETE' });
      router.refresh();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : 'That didn’t work');
    } finally {
      setPending(null);
    }
  };

  const rowCls = 'flex flex-wrap items-center justify-between gap-3 px-4 py-3';

  return (
    <section id="sign-in" aria-labelledby="sign-in-heading" className="flex max-w-[560px] flex-col gap-[14px]">
      <h2 id="sign-in-heading" className="m-0 text-[18px] font-semibold">Sign-in methods</h2>
      <p className="m-0 text-[14px] text-muted">Any of these logs in to the same account. The last one left can’t be removed.</p>
      {message && <FormMessage>{message}</FormMessage>}
      <ul className="m-0 flex list-none flex-col rounded border border-line p-0">
        <li className={`${rowCls} border-b border-line`}>
          <div className="flex flex-col">
            <span className="font-medium text-ink">Email and password</span>
            <span className="text-[13px] text-muted">{hasPassword ? 'Set' : 'No password yet. Set one under Account above.'}</span>
          </div>
          {hasPassword && (
            <button
              type="button"
              className="oa-btn h-9 px-3 text-[13px]"
              disabled={onlyOne || pending !== null}
              aria-describedby={onlyOne ? 'last-method' : undefined}
              onClick={() => {
                if (window.confirm('Remove your password? You will sign in with Google or GitHub only.')) {
                  void remove('password', '/api/account/password');
                }
              }}
            >
              {pending === 'password' ? 'Removing…' : 'Remove password'}
            </button>
          )}
        </li>
        {rows.map((row, i) => {
          const link = linked.find((l) => l.provider === row.id);
          return (
            <li key={row.id} className={`${rowCls} ${i < rows.length - 1 ? 'border-b border-line' : ''}`}>
              <div className="flex flex-col">
                <span className="font-medium text-ink">{row.name}</span>
                <span className="text-[13px] text-muted">{link ? `Linked since ${dateLabel(link.linkedAt)}` : 'Not linked'}</span>
              </div>
              {link ? (
                <button
                  type="button"
                  className="oa-btn h-9 px-3 text-[13px]"
                  disabled={onlyOne || pending !== null}
                  aria-describedby={onlyOne ? 'last-method' : undefined}
                  onClick={() => void remove(row.id, `/api/account/providers/${row.id}`)}
                >
                  {pending === row.id ? 'Unlinking…' : `Unlink ${row.name}`}
                </button>
              ) : (
                row.configured && (
                  <button
                    type="button"
                    className="oa-btn h-9 px-3 text-[13px]"
                    disabled={pending !== null}
                    onClick={() => {
                      setPending(row.id);
                      void loginWith(row.id as 'google' | 'github', '/settings#sign-in').catch(() => setPending(null));
                    }}
                  >
                    {pending === row.id ? `Opening ${row.name}…` : `Link ${row.name}`}
                  </button>
                )
              )}
            </li>
          );
        })}
      </ul>
      {onlyOne && (
        <p id="last-method" className="m-0 text-[13px] text-muted">
          This is your only way to sign in, so it can’t be removed until you add another.
        </p>
      )}
    </section>
  );
}
