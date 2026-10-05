'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { login, logout, signup, type SignupInput } from '@/lib/client/auth';
import { setSessionUser } from './useSession';
import { safeRedirectPath } from '@/lib/validation';

function useSubmit<A extends unknown[]>(action: (...args: A) => Promise<void>) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (...args: A) => {
    setPending(true);
    setError(null);
    try {
      await action(...args);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setPending(false);
    }
  };

  return { submit, pending, error };
}

export function useLogin(next: string | null) {
  const router = useRouter();
  return useSubmit(async (email: string, password: string) => {
    setSessionUser(await login(email, password));
    router.replace(safeRedirectPath(next));
    router.refresh();
  });
}

export function useSignup() {
  const router = useRouter();
  return useSubmit(async (input: SignupInput) => {
    setSessionUser(await signup(input));
    router.replace('/');
    router.refresh();
  });
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
