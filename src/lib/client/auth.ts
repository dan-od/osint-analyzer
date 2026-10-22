import { apiRequest } from './http';
import type { PublicUser } from '@/types/account';

export interface SignupInput {
  name: string;
  email: string;
  password: string;
}

export async function fetchCurrentUser(): Promise<PublicUser | null> {
  const data = await apiRequest<{ user: PublicUser | null }>('/api/auth/me', { cache: 'no-store' });
  return data.user;
}

/** Email + password sign-in through Auth.js; returns an error message or null */
/** Thrown by login(); `code` is "unverified" when the email still needs confirming */
export class LoginError extends Error {
  constructor(readonly code: string) {
    super(LOGIN_ERRORS[code] ?? LOGIN_ERRORS.invalid);
  }
}

export async function login(email: string, password: string): Promise<void> {
  const { signIn } = await import('next-auth/react');
  const result = await signIn('credentials', { email, password, redirect: false });
  if (result?.error) throw new LoginError(result.code ?? 'invalid');
}

const LOGIN_ERRORS: Record<string, string> = {
  invalid: 'Invalid email or password',
  disabled: 'This account has been disabled. Contact the administrator.',
  rate_limited: 'Too many login attempts. Try again later.',
  unverified: 'Confirm your email address first. Use the link we sent you, or send a new one.',
};

/** Google or GitHub: leaves the page for the provider and comes back to `next` */
export async function loginWith(provider: 'google' | 'github', next: string): Promise<void> {
  const { signIn } = await import('next-auth/react');
  await signIn(provider, { redirectTo: next });
}

export type SignupResult = { email: string; delivery: 'email' | 'console' | 'failed' };

/** Creates an unconfirmed account; the person signs in after confirming the email */
export async function signup(input: SignupInput): Promise<SignupResult> {
  return apiRequest<SignupResult>('/api/auth/signup', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function logout(): Promise<void> {
  await apiRequest('/api/auth/logout', { method: 'POST' });
}
