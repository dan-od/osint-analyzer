'use client';

import { useState, type FormEvent, type ReactNode } from 'react';
import Link from 'next/link';
import { CornerTicks } from '@/components/decor';
import { useLogin, useSignup } from '@/hooks/useAuthActions';

export type AuthTab = 'login' | 'signup';

/** Messages are neutral: red/amber/green are reserved for verdicts */
export function FormMessage({ children }: { children: ReactNode }) {
  return (
    <div role="alert" className="rounded border border-line-strong border-l-[3px] border-l-accent bg-ground px-3 py-[10px] text-[14px] text-ink">
      {children}
    </div>
  );
}

export function Field({
  id,
  label,
  mono,
  ...input
}: React.InputHTMLAttributes<HTMLInputElement> & { id: string; label: string; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-[6px]">
      <label htmlFor={id} className="oa-label">{label}</label>
      <input id={id} {...input} className={`oa-input ${mono ? 'oa-mono' : ''} ${input.className ?? ''}`} />
    </div>
  );
}

export default function AuthCard({
  initialTab,
  next,
  signupsOpen,
  minPasswordLength,
}: {
  initialTab: AuthTab;
  next: string | null;
  signupsOpen: boolean;
  minPasswordLength: number;
}) {
  const [tab, setTab] = useState<AuthTab>(initialTab);

  const switchTo = (t: AuthTab) => {
    setTab(t);
    // Keep the address bar in step without a navigation
    window.history.replaceState(null, '', t === 'login' ? `/login${next ? `?next=${encodeURIComponent(next)}` : ''}` : '/signup');
  };

  const tabCls = (active: boolean) =>
    `-mb-px border-0 border-b-2 bg-transparent px-[14px] py-[10px] text-[15px] cursor-pointer ${
      active ? 'border-accent font-semibold text-ink-strong' : 'border-transparent font-medium text-muted'
    }`;

  return (
    <div className="relative box-border flex w-full max-w-[440px] flex-col gap-[18px] rounded border border-line bg-panel p-7">
      <CornerTicks tone="accent" />
      <div role="tablist" className="flex border-b border-line">
        <button role="tab" type="button" aria-selected={tab === 'login'} className={tabCls(tab === 'login')} onClick={() => switchTo('login')}>
          Log in
        </button>
        <button role="tab" type="button" aria-selected={tab === 'signup'} className={tabCls(tab === 'signup')} onClick={() => switchTo('signup')}>
          Create account
        </button>
      </div>
      {tab === 'login' ? <LoginPanel next={next} /> : <SignupPanel open={signupsOpen} minPasswordLength={minPasswordLength} />}
      <p className="m-0 text-[13px] text-skip">
        No account? You can still <Link href="/">check one thing at a time</Link> without logging in.
      </p>
    </div>
  );
}

function LoginPanel({ next }: { next: string | null }) {
  const { submit, pending, error } = useLogin(next);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    void submit(email, password);
  };
  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-[18px]">
      <p className="m-0 text-[14px] text-muted">Log in for bulk checks, IP lookups and your own API keys.</p>
      {error && <FormMessage>{error}</FormMessage>}
      <Field id="email" label="Email" type="email" autoComplete="email" required placeholder="you@team.example" value={email} onChange={(e) => setEmail(e.target.value)} />
      <Field id="pw" label="Password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
      <button type="submit" disabled={pending} className="oa-btn-primary mt-1 h-12 text-[16px]">
        {pending ? 'Logging in…' : 'Log in'}
      </button>
    </form>
  );
}

function SignupPanel({ open, minPasswordLength }: { open: boolean; minPasswordLength: number }) {
  const { submit, pending, error } = useSignup();
  const [values, setValues] = useState({ name: '', email: '', password: '', inviteCode: '' });
  const set = (field: keyof typeof values) => (e: React.ChangeEvent<HTMLInputElement>) => setValues((v) => ({ ...v, [field]: e.target.value }));
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    void submit(values);
  };

  if (!open) {
    return <p className="m-0 text-[14px] text-muted">Sign-ups are closed right now. Ask Daniel for access.</p>;
  }
  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-[18px]">
      <p className="m-0 text-[14px] text-muted">Accounts are for the SOC rotation. You need the invite code from Daniel or Prof. Lee.</p>
      {error && <FormMessage>{error}</FormMessage>}
      <Field id="name" label="Name" type="text" autoComplete="name" required maxLength={100} placeholder="Your name" value={values.name} onChange={set('name')} />
      <Field id="email" label="Email" type="email" autoComplete="email" required placeholder="you@team.example" value={values.email} onChange={set('email')} />
      <Field
        id="pw"
        label="Password"
        type="password"
        autoComplete="new-password"
        required
        minLength={minPasswordLength}
        placeholder={`${minPasswordLength} characters or more`}
        value={values.password}
        onChange={set('password')}
      />
      <Field id="code" label="Invite code" type="text" autoComplete="off" required mono placeholder="SOC-2026-…" value={values.inviteCode} onChange={set('inviteCode')} />
      <button type="submit" disabled={pending} className="oa-btn-primary mt-1 h-12 text-[16px]">
        {pending ? 'Creating account…' : 'Create account'}
      </button>
    </form>
  );
}
