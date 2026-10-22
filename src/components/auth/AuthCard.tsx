'use client';

import { useEffect, useId, useRef, useState, type FormEvent, type KeyboardEvent, type ReactNode } from 'react';
import Link from 'next/link';
import { CornerTicks } from '@/components/decor';
import { useLogin, useSignup } from '@/hooks/useAuthActions';
import { loginWith } from '@/lib/client/auth';
import { safeRedirectPath } from '@/lib/validation';
import VerificationNotice from './VerificationNotice';

export type AuthTab = 'login' | 'signup';
export type SsoProvider = { id: 'google' | 'github'; name: string };

/** Messages are neutral: red/amber/green are reserved for verdicts */
export function FormMessage({ children, id }: { children: ReactNode; id?: string }) {
  return (
    <div id={id} role="alert" className="rounded border border-line-strong border-l-[3px] border-l-accent bg-ground px-3 py-[10px] text-[14px] text-ink">
      {children}
    </div>
  );
}

export function Field({
  id,
  label,
  mono,
  hint,
  ...input
}: React.InputHTMLAttributes<HTMLInputElement> & { id: string; label: string; mono?: boolean; hint?: string }) {
  const hintId = hint ? `${id}-hint` : undefined;
  const describedBy = [input['aria-describedby'], hintId].filter(Boolean).join(' ') || undefined;
  return (
    <div className="flex flex-col gap-[6px]">
      <label htmlFor={id} className="oa-label">{label}</label>
      <input id={id} {...input} aria-describedby={describedBy} className={`oa-input ${mono ? 'oa-mono' : ''} ${input.className ?? ''}`} />
      {hint && (
        <span id={hintId} className="text-[12px] text-muted">
          {hint}
        </span>
      )}
    </div>
  );
}

export default function AuthCard({
  initialTab,
  next,
  minPasswordLength,
  providers,
  error,
}: {
  initialTab: AuthTab;
  next: string | null;
  minPasswordLength: number;
  providers: SsoProvider[];
  /** From ?error= after a failed Google/GitHub sign-in */
  error: string | null;
}) {
  const [tab, setTab] = useState<AuthTab>(initialTab);
  // After a password signup the card only shows "check your inbox"
  const [signupSent, setSignupSent] = useState(false);
  const tabs = useRef<Record<AuthTab, HTMLButtonElement | null>>({ login: null, signup: null });
  const base = useId();

  const switchTo = (t: AuthTab, focus = false) => {
    setTab(t);
    if (focus) tabs.current[t]?.focus();
    // Keep the address bar in step without a navigation
    window.history.replaceState(null, '', t === 'login' ? `/login${next ? `?next=${encodeURIComponent(next)}` : ''}` : '/signup');
  };

  // WAI-ARIA tabs: arrow keys move between the two tabs
  const onTabKey = (e: KeyboardEvent) => {
    if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) {
      e.preventDefault();
      switchTo(e.key === 'Home' ? 'login' : e.key === 'End' ? 'signup' : tab === 'login' ? 'signup' : 'login', true);
    }
  };

  const tabCls = (active: boolean) =>
    `-mb-px border-0 border-b-2 bg-transparent px-[14px] py-[10px] text-[15px] cursor-pointer ${
      active ? 'border-accent font-semibold text-ink-strong' : 'border-transparent font-medium text-muted'
    }`;

  const tabButton = (t: AuthTab, label: string) => (
    <button
      ref={(el) => {
        tabs.current[t] = el;
      }}
      id={`${base}-tab-${t}`}
      role="tab"
      type="button"
      aria-selected={tab === t}
      aria-controls={`${base}-panel`}
      tabIndex={tab === t ? 0 : -1}
      className={tabCls(tab === t)}
      onClick={() => switchTo(t)}
      onKeyDown={onTabKey}
    >
      {label}
    </button>
  );

  return (
    <div className="relative box-border flex w-full max-w-[440px] flex-col gap-[18px] rounded border border-line bg-panel p-7 max-[420px]:p-5">
      <CornerTicks tone="accent" />
      <h1 className="oa-sr">{tab === 'login' ? 'Log in' : 'Create an account'}</h1>
      <div role="tablist" aria-label="Log in or create an account" className="flex border-b border-line">
        {tabButton('login', 'Log in')}
        {tabButton('signup', 'Create account')}
      </div>
      <div id={`${base}-panel`} role="tabpanel" aria-labelledby={`${base}-tab-${tab}`} className="flex flex-col gap-[18px]">
        {error && <FormMessage>{error}</FormMessage>}
        {providers.length > 0 && !(tab === 'signup' && signupSent) && (
          <>
            <SsoButtons providers={providers} next={tab === 'login' ? safeRedirectPath(next) : '/'} verb={tab === 'login' ? 'Continue' : 'Sign up'} />
            <div className="flex items-center gap-3 text-[13px] text-muted" role="separator" aria-label="or use your email">
              <span className="h-px flex-1 bg-line" aria-hidden="true" />
              <span aria-hidden="true">or with email</span>
              <span className="h-px flex-1 bg-line" aria-hidden="true" />
            </div>
          </>
        )}
        {tab === 'login' ? <LoginPanel next={next} /> : <SignupPanel minPasswordLength={minPasswordLength} onSent={() => setSignupSent(true)} />}
      </div>
      <p className="m-0 text-[13px] text-muted">
        No account? You can still <Link href="/">check one thing at a time</Link> without logging in.
      </p>
    </div>
  );
}

function ProviderIcon({ id }: { id: SsoProvider['id'] }) {
  // Single-colour marks so the card stays within the interface palette
  return id === 'google' ? (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false">
      <path d="M21.35 11.1H12v3.2h5.35c-.5 2.5-2.6 3.9-5.35 3.9a6.2 6.2 0 1 1 0-12.4c1.55 0 2.95.55 4.05 1.5l2.4-2.4A9.6 9.6 0 1 0 12 21.6c5.5 0 9.6-3.9 9.6-9.6 0-.3 0-.6-.05-.9h-.2Z" />
    </svg>
  ) : (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false">
      <path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.9 1.52 2.34 1.08 2.91.83.09-.65.35-1.08.63-1.33-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.02a9.5 9.5 0 0 1 5 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.38.2 2.4.1 2.65.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10 10 0 0 0 12 2Z" />
    </svg>
  );
}

function SsoButtons({ providers, next, verb }: { providers: SsoProvider[]; next: string; verb: string }) {
  const [pending, setPending] = useState<string | null>(null);
  return (
    <div className="flex flex-col gap-[10px]">
      {providers.map((p) => (
        <button
          key={p.id}
          type="button"
          disabled={pending !== null}
          onClick={() => {
            setPending(p.id);
            void loginWith(p.id, next).catch(() => setPending(null));
          }}
          className="oa-btn h-12 w-full gap-[10px] text-[15px] font-medium"
        >
          <ProviderIcon id={p.id} />
          {pending === p.id ? `Opening ${p.name}…` : `${verb} with ${p.name}`}
        </button>
      ))}
    </div>
  );
}

function LoginPanel({ next }: { next: string | null }) {
  const { submit, pending, error, errorCode } = useLogin(next);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const errorId = useId();
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    void submit(email, password);
  };
  const invalid = error ? { 'aria-invalid': true, 'aria-describedby': errorId } : {};
  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-[18px]" noValidate={false}>
      {error && <FormMessage id={errorId}>{error}</FormMessage>}
      {errorCode === 'unverified' && <VerificationNotice email={email.trim().toLowerCase()} delivery={null} />}
      <Field id="email" label="Email" type="email" autoComplete="email" required placeholder="you@team.example" value={email} onChange={(e) => setEmail(e.target.value)} {...invalid} />
      <Field id="pw" label="Password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} {...invalid} />
      <button type="submit" disabled={pending} className="oa-btn-primary mt-1 h-12 text-[16px]">
        {pending ? 'Logging in…' : 'Log in'}
      </button>
    </form>
  );
}

function SignupPanel({ minPasswordLength, onSent }: { minPasswordLength: number; onSent: () => void }) {
  const { submit, pending, error, sent } = useSignup();
  const [values, setValues] = useState({ name: '', email: '', password: '' });
  const errorId = useId();
  const set = (field: keyof typeof values) => (e: React.ChangeEvent<HTMLInputElement>) => setValues((v) => ({ ...v, [field]: e.target.value }));
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    void submit(values);
  };
  const invalid = error ? { 'aria-invalid': true, 'aria-describedby': errorId } : {};

  useEffect(() => {
    if (sent) onSent();
  }, [sent, onSent]);

  if (sent) return <VerificationNotice email={sent.email} delivery={sent.delivery} />;

  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-[18px]">
      <p className="m-0 text-[14px] text-muted">Free for anyone. An account unlocks IP checks, bulk jobs and your own API keys.</p>
      {error && <FormMessage id={errorId}>{error}</FormMessage>}
      <Field id="name" label="Name" type="text" autoComplete="name" required maxLength={100} placeholder="Your name" value={values.name} onChange={set('name')} {...invalid} />
      <Field id="email" label="Email" type="email" autoComplete="email" required placeholder="you@team.example" value={values.email} onChange={set('email')} {...invalid} />
      <Field
        id="pw"
        label="Password"
        type="password"
        autoComplete="new-password"
        required
        minLength={minPasswordLength}
        hint={`${minPasswordLength} characters or more`}
        value={values.password}
        onChange={set('password')}
        {...invalid}
      />
      <button type="submit" disabled={pending} className="oa-btn-primary mt-1 h-12 text-[16px]">
        {pending ? 'Creating account…' : 'Create account'}
      </button>
      <p className="m-0 text-[13px] text-muted">
        By creating an account you agree to the <Link href="/terms">Terms</Link> and <Link href="/privacy">Privacy Policy</Link>.
      </p>
    </form>
  );
}
