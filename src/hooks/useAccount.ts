'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { apiRequest } from '@/lib/client/http';
import { setSessionUser } from './useSession';
import type { PublicUser } from '@/types/account';

function useAction<A extends unknown[]>(action: (...args: A) => Promise<string>) {
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const run = async (...args: A) => {
    setPending(true);
    setMessage(null);
    try {
      setMessage(await action(...args));
      return true;
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'Something went wrong');
      return false;
    } finally {
      setPending(false);
    }
  };
  return { run, pending, message };
}

export function useAccount() {
  const router = useRouter();
  const profile = useAction(async (name: string, email: string) => {
    const { user } = await apiRequest<{ user: PublicUser }>('/api/account', {
      method: 'PATCH',
      body: JSON.stringify({ name, email }),
    });
    setSessionUser(user);
    router.refresh();
    return 'Saved.';
  });
  const password = useAction(async (current: string, next: string) => {
    await apiRequest('/api/account/password', { method: 'POST', body: JSON.stringify({ current, next }) });
    return 'Password changed. Other browsers have been signed out.';
  });
  return { profile, password };
}
