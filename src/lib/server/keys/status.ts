// What the Settings page is allowed to know about a user's keys: masked hints
// and usage counters, never key material.
import { SERVICES, maskKey, type ServiceId } from '@/lib/services';
import type { ApiKeyStatus } from '@/types/account';
import { listUserKeyHints } from './store';
import { usedInPeriod, usedToday } from './usage';

export function keyStatusesFor(userId: number, only?: ServiceId): ApiKeyStatus[] {
  const hints = listUserKeyHints(userId);
  return SERVICES.filter((s) => !only || s.id === only).map((service) => {
    const hint = hints.get(service.id);
    const quota = service.quota;
    const usedThisPeriod = quota ? usedInPeriod(userId, service.id, 'user', quota.period) : null;
    const userToday = usedToday(userId, service.id, 'user');
    return {
      service: service.id,
      maskedKey: hint ? maskKey(hint.last4) : null,
      updatedAt: hint ? new Date(hint.updatedAt).toISOString() : null,
      serverFallback: !!process.env[service.envVar]?.trim(),
      usage: {
        userToday,
        serverToday: usedToday(userId, service.id, 'server'),
        quota: quota
          ? {
              limit: quota.limit,
              period: quota.period,
              used: usedThisPeriod!,
              remaining: Math.max(0, quota.limit - usedThisPeriod!),
              dailyCap: quota.dailyCap
                ? { limit: quota.dailyCap, used: userToday, remaining: Math.max(0, quota.dailyCap - userToday) }
                : null,
            }
          : null,
      },
    };
  });
}
