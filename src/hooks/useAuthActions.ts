'use client';

import { useState } from 'react';
import { LoginError, type SignupResult } from '@/lib/client/auth';
import { useRouter } from 'next/navigation';
import { fetchCurrentUser, login, logout, signup, type SignupInput } from '@/lib/client/auth';
import { setSessionUser } from './useSession';
import { safeRedirectPath } from '@/lib/validation';

function useSubmit<A extends unknown[]>(action: (...args: A) => Promise<void>) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);

  const submit = async (...args: A) => {
    setPending(true);
    setError(null);
    setErrorCode(null);
    try {
      await action(...args);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
      setErrorCode(err instanceof LoginError ? err.code : null);
    } finally {
      setPending(false);
    }
  };

  return { submit, pending, error, errorCode };
}

export function useLogin(next: string | null) {
  const router = useRouter();
  return useSubmit(async (email: string, password: string) => {
    await login(email, password);
    setSessionUser(await fetchCurrentUser());
    router.replace(safeRedirectPath(next));
    router.refresh();
  });
}

/** Signup ends at "check your inbox": no sign-in until the email is confirmed */
export function useSignup() {
  const [sent, setSent] = useState<SignupResult | null>(null);
  const state = useSubmit(async (input: SignupInput) => {
    setSent(await signup(input));
  });
  return { ...state, sent };
}

export function useLogout() {
  const router = useRouter();
  return useSubmit(async () => {
    await logout();
    setSessionUser(null);
    router.replace('/');
    router.refresh();
  });
}
