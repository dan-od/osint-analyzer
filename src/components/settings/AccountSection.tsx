'use client';

import { useState, type FormEvent } from 'react';
import { useAccount } from '@/hooks/useAccount';
import type { PublicUser } from '@/types/account';

const input = 'oa-input h-10 bg-panel text-[15px]';

export default function AccountSection({
  user,
  minPasswordLength,
  hasPassword,
  pendingEmail,
}: {
  user: PublicUser;
  minPasswordLength: number;
  hasPassword: boolean;
  /** A new address waiting for its confirmation link */
  pendingEmail: string | null;
}) {
  const { profile, password } = useAccount();
  const [name, setName] = useState(user.name);
  const [email, setEmail] = useState(user.email);
  const [changing, setChanging] = useState(false);
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');

  const saveProfile = (e: FormEvent) => {
    e.preventDefault();
    void profile.run(name, email);
  };

  const savePassword = async (e: FormEvent) => {
    e.preventDefault();
    if (await password.run(current, next)) {
      setCurrent('');
      setNext('');
      setChanging(false);
    }
  };

  const profileInvalid = profile.failed && profile.message ? { 'aria-invalid': true, 'aria-describedby': 'profile-msg' } : {};
  const passwordInvalid = password.failed && password.message ? { 'aria-invalid': true, 'aria-describedby': 'password-msg' } : {};

  return (
    <section id="account" aria-label="Account" className="flex max-w-[560px] flex-col gap-[14px]">
      <h2 className="m-0 text-[18px] font-semibold">Account</h2>
      <form onSubmit={saveProfile} className="flex flex-col gap-[14px]">
        <div className="flex flex-col gap-[6px]">
          <label htmlFor="n" className="oa-label">Name</label>
          <input id="n" type="text" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} className={input} {...profileInvalid} />
        </div>
        <div className="flex flex-col gap-[6px]">
          <label htmlFor="e" className="oa-label">Email</label>
          <input id="e" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className={input} {...profileInvalid} aria-describedby={pendingEmail ? 'e-pending' : profileInvalid['aria-describedby']} />
          {pendingEmail && (
            <span id="e-pending" className="text-[13px] text-muted">
              Waiting for you to confirm {pendingEmail}. Until then your account uses {user.email}.
            </span>
          )}
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <button type="submit" disabled={profile.pending} className="oa-btn-primary h-10 px-4 text-[14px]">
            {profile.pending ? 'Saving…' : 'Save changes'}
          </button>
          <button type="button" onClick={() => setChanging((v) => !v)} className="oa-btn">
            {hasPassword ? 'Change password' : 'Set a password'}
          </button>
          {profile.message && (
            <span id="profile-msg" role={profile.failed ? 'alert' : 'status'} className={`text-[13px] ${profile.failed ? 'text-ink' : 'text-muted'}`}>
              {profile.message}
            </span>
          )}
        </div>
      </form>

      {changing && (
        <form onSubmit={savePassword} className="flex flex-col gap-[14px] rounded border border-line p-4">
          {hasPassword && (
            <div className="flex flex-col gap-[6px]">
              <label htmlFor="pw-current" className="oa-label">Current password</label>
              <input id="pw-current" type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} className={input} {...passwordInvalid} />
            </div>
          )}
          <div className="flex flex-col gap-[6px]">
            <label htmlFor="pw-new" className="oa-label">New password</label>
            <input
              id="pw-new"
              type="password"
              autoComplete="new-password"
              required
              minLength={minPasswordLength}
              placeholder={`${minPasswordLength} characters or more`}
              value={next}
              onChange={(e) => setNext(e.target.value)}
              className={input}
              {...passwordInvalid}
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="submit" disabled={password.pending} className="oa-btn-primary h-10 px-4 text-[14px]">
              {password.pending ? 'Saving…' : hasPassword ? 'Change password' : 'Set password'}
            </button>
            <button type="button" onClick={() => setChanging(false)} className="oa-btn">Cancel</button>
          </div>
        </form>
      )}
      {password.message && !changing && <span role="status" className="text-[13px] text-muted">{password.message}</span>}
      {password.message && changing && (
        <span id="password-msg" role={password.failed ? 'alert' : 'status'} className="text-[13px] text-ink">
          {password.message}
        </span>
      )}
    </section>
  );
}
