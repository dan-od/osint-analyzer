'use client';

import { useId, useState, type FormEvent } from 'react';
import { FormMessage } from '@/components/auth/AuthCard';
import { apiRequest } from '@/lib/client/http';
import { setSessionUser } from '@/hooks/useSession';

/** Removes the account and everything tied to it (sessions, keys, jobs, history) */
export default function DeleteAccount({ email }: { email: string }) {
  const [open, setOpen] = useState(false);
  const [confirm, setConfirm] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const errorId = useId();
  const matches = confirm.trim().toLowerCase() === email.toLowerCase();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setPending(true);
    setError(null);
    try {
      await apiRequest('/api/account', { method: 'DELETE', body: JSON.stringify({ confirm }) });
      setSessionUser(null);
      window.location.assign('/');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'That didn’t work');
      setPending(false);
    }
  };

  return (
    <section id="delete" aria-labelledby="delete-heading" className="flex max-w-[560px] flex-col gap-[14px]">
      <h2 id="delete-heading" className="m-0 text-[18px] font-semibold">Delete my account</h2>
      <p className="m-0 text-[14px] text-muted">
        Removes your account, sign-in methods, saved API keys, recent checks and bulk jobs straight away. It can’t be undone.
      </p>
      {!open ? (
        <div>
          <button type="button" className="oa-btn" onClick={() => setOpen(true)}>
            Delete my account…
          </button>
        </div>
      ) : (
        <form onSubmit={submit} aria-label="Confirm account deletion" className="flex flex-col gap-[14px] rounded border border-line p-4">
          {error && <FormMessage id={errorId}>{error}</FormMessage>}
          <div className="flex flex-col gap-[6px]">
            <label htmlFor="delete-confirm" className="oa-label">
              Type your email, <span className="text-ink">{email}</span>, to confirm
            </label>
            <input
              id="delete-confirm"
              type="email"
              autoComplete="off"
              required
              autoFocus
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? errorId : undefined}
              className="oa-input h-10 bg-panel text-[15px]"
            />
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="submit" disabled={pending || !matches} className="oa-btn-primary h-10 px-4 text-[14px]">
              {pending ? 'Deleting…' : 'Delete everything'}
            </button>
            <button type="button" className="oa-btn" onClick={() => setOpen(false)}>
              Cancel
            </button>
          </div>
        </form>
      )}
    </section>
  );
}
