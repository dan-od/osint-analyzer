'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { apiRequest } from '@/lib/client/http';
import { setSessionUser } from './useSession';
import type { PublicUser } from '@/types/account';
import { deliveryText, type Delivery } from '@/components/auth/VerificationNotice';

function useAction<A extends unknown[]>(action: (...args: A) => Promise<string>) {
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const run = async (...args: A) => {
    setPending(true);
    setMessage(null);
    try {
      setMessage(await action(...args));
      setFailed(false);
      return true;
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'Something went wrong');
      setFailed(true);
      return false;
    } finally {
      setPending(false);
    }
  };
  return { run, pending, message, failed };
}

export function useAccount() {
  const router = useRouter();
  const profile = useAction(async (name: string, email: string) => {
    const { user, pendingEmail, delivery } = await apiRequest<{
      user: PublicUser;
      pendingEmail: string | null;
      delivery: Delivery | null;
    }>('/api/account', {
      method: 'PATCH',
      body: JSON.stringify({ name, email }),
    });
    setSessionUser(user);
    router.refresh();
    if (!pendingEmail || !delivery) return 'Saved.';
    if (delivery === 'failed') throw new Error(deliveryText('failed', pendingEmail));
    return `Saved. ${deliveryText(delivery, pendingEmail).replace('a confirmation link', 'a link')} Your email changes to ${pendingEmail} when you confirm it.`;
  });
  const password = useAction(async (current: string, next: string) => {
    const { created } = await apiRequest<{ created: boolean }>('/api/account/password', { method: 'POST', body: JSON.stringify({ current, next }) });
    router.refresh();
    return created ? 'Password set. You can now log in with your email too.' : 'Password changed. Other browsers have been signed out.';
  });
  return { profile, password };
}
