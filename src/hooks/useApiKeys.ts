'use client';

import { useCallback, useEffect, useState } from 'react';
import { deleteApiKey, fetchApiKeys, saveApiKey } from '@/lib/client/keys';
import type { ServiceId } from '@/lib/services';
import type { ApiKeysOverview, ApiKeyStatus } from '@/types/account';

export interface KeyRowState {
  pending: boolean;
  error: string | null;
}

export function useApiKeys() {
  const [overview, setOverview] = useState<ApiKeysOverview | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [rows, setRows] = useState<Partial<Record<ServiceId, KeyRowState>>>({});

  const load = useCallback(async () => {
    try {
      setOverview(await fetchApiKeys());
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Could not load your keys');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const mutate = async (service: ServiceId, action: () => Promise<ApiKeyStatus>): Promise<boolean> => {
    setRows((r) => ({ ...r, [service]: { pending: true, error: null } }));
    try {
      const status = await action();
      setOverview((o) => o && { ...o, keys: o.keys.map((k) => (k.service === service ? status : k)) });
      setRows((r) => ({ ...r, [service]: { pending: false, error: null } }));
      return true;
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Request failed';
      setRows((r) => ({ ...r, [service]: { pending: false, error } }));
      return false;
    }
  };

  return {
    overview,
    loadError,
    rowState: (service: ServiceId): KeyRowState => rows[service] ?? { pending: false, error: null },
    saveKey: (service: ServiceId, key: string) => mutate(service, () => saveApiKey(service, key)),
    removeKey: (service: ServiceId) => mutate(service, () => deleteApiKey(service)),
    reload: load,
  };
}
