'use client';

import { useId, useState, type FormEvent } from 'react';
import Link from 'next/link';
import { Field, FormMessage } from '@/components/auth/AuthCard';
import { ApiError, apiRequest } from '@/lib/client/http';
import ResendForm from './ResendForm';

type Done = { purpose: 'signup' | 'email-change'; email: string; merged: boolean; signedIn: boolean };

/**
 * Confirms a link and signs in. A signup must give the password chosen at
 * signup, so a link that reaches someone else's inbox is useless on its own.
 * A POST, so link scanners can't use it.
 */
export default function ConfirmEmail({ token, purpose, email }: { token: string; purpose: 'signup' | 'email-change'; email: string }) {
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [done, setDone] = useState<Done | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);
  const errorId = useId();

  const confirm = async (e?: FormEvent) => {
    e?.preventDefault();
    setPending(true);
    setError(null);
    try {
      setDone(await apiRequest<Done>('/api/auth/verify-email', { method: 'POST', body: JSON.stringify({ token, password }) }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'That didn’t work');
      if (err instanceof ApiError && (err.status === 423 || err.status === 410)) setLocked(true);
      setPassword('');
    } finally {
      setPending(false);
    }
  };

  if (done) {
    const headline =
      done.purpose === 'email-change'
        ? `Your account now uses ${done.email}.`
        : done.merged
          ? `${done.email} is confirmed. It already had an account (signed up with Google or GitHub), so you're signed in to that one, and your password now works for it too.`
          : `${done.email} is confirmed and you're signed in.`;
    return (
      <div className="flex flex-col gap-4" role="status">
        <p className="m-0 text-[16px] text-ink">{headline}</p>
        {done.signedIn ? (
          // A full page load, so the header picks up the new session
          <a href={done.purpose === 'email-change' ? '/settings#account' : '/'} className="oa-btn-primary h-12 text-[16px]">
            {done.purpose === 'email-change' ? 'Back to Settings' : 'Start checking'}
          </a>
        ) : (
          <Link href="/login" className="oa-btn-primary h-12 text-[16px]">Log in</Link>
        )}
      </div>
    );
  }

  if (locked) {
    return (
      <div className="flex flex-col gap-4">
        <FormMessage>{error}</FormMessage>
        <ResendForm defaultEmail={purpose === 'signup' ? email : ''} />
      </div>
    );
  }

  if (purpose === 'email-change') {
    return (
      <div className="flex flex-col gap-4">
        {error && <FormMessage>{error}</FormMessage>}
        <p className="m-0 text-ink-body">
          Confirm <span className="text-ink">{email}</span> as your account&apos;s new email address.
        </p>
        <button type="button" onClick={() => void confirm()} disabled={pending} className="oa-btn-primary h-12 text-[16px]">
          {pending ? 'Confirming…' : 'Confirm new address'}
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={confirm} className="flex flex-col gap-4">
      {error && <FormMessage id={errorId}>{error}</FormMessage>}
      <p className="m-0 text-ink-body">
        Confirming <span className="text-ink break-all">{email}</span>. Enter the password you chose when you signed up to finish
        and sign in.
      </p>
      <Field
        id="confirm-password"
        label="Password"
        type="password"
        autoComplete="current-password"
        required
        autoFocus
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? errorId : undefined}
      />
      <button type="submit" disabled={pending || !password} className="oa-btn-primary h-12 text-[16px]">
        {pending ? 'Confirming…' : 'Confirm and sign in'}
      </button>
      <p className="m-0 text-[13px] text-muted">
        Didn&apos;t sign up? Ignore this. Nobody can use your address without this password.
      </p>
    </form>
  );
}
