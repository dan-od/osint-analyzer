'use client';

import { useEffect, useSyncExternalStore } from 'react';
import { fetchCurrentUser } from '@/lib/client/auth';
import type { PublicUser } from '@/types/account';

// One shared session snapshot for every component on the page (header, pages)

export type SessionStatus = 'loading' | 'authenticated' | 'anonymous';

interface SessionState {
  status: SessionStatus;
  user: PublicUser | null;
}

let state: SessionState = { status: 'loading', user: null };
let inflight: Promise<void> | null = null;
const listeners = new Set<() => void>();

function emit(next: SessionState) {
  state = next;
  listeners.forEach((l) => l());
}

export function setSessionUser(user: PublicUser | null) {
  emit({ status: user ? 'authenticated' : 'anonymous', user });
}

export function refreshSession(): Promise<void> {
  inflight ??= fetchCurrentUser()
    .then(setSessionUser)
    .catch(() => setSessionUser(null))
    .finally(() => {
      inflight = null;
    });
  return inflight;
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

const loadingState: SessionState = { status: 'loading', user: null };

export function useSession(): SessionState & { refresh: () => Promise<void> } {
  const snapshot = useSyncExternalStore(subscribe, () => state, () => loadingState);
  useEffect(() => {
    if (state.status === 'loading') void refreshSession();
  }, []);
  return { ...snapshot, refresh: refreshSession };
}
