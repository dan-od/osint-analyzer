// Decides which API key a lookup may use for each service:
//   1. the user's own key (within its free-tier quota)
//   2. the server's env key (single lookups only)
//   3. otherwise the source is skipped, with a note telling the user why.
// Keys are never shared or rotated between users.
import { getService, type ServiceId } from '@/lib/services';
import type { PublicUser } from '@/types/account';
import type { SkippedSource } from '@/types';
import { getUserKey } from './store';
import { recordUsage, usedInPeriod, type KeySource } from './usage';
import { takeSlot } from './limiter';

export interface KeyGrant {
  ok: true;
  service: ServiceId;
  key: string;
  source: KeySource;
}

export interface KeySkip {
  ok: false;
  service: ServiceId;
  reason: string;
}

export interface KeyResolverOptions {
  user: PublicUser | null;
  /** Bulk mode runs on the user's own quotas only */
  allowServerKeys: boolean;
  /** How long to wait for a per-minute slot before skipping (bulk waits, single lookups don't) */
  maxRateWaitMs: number;
  /** Bulk option: treat every keyed source as unavailable */
  freeSourcesOnly?: boolean;
}

const RESETS = {
  day: 'Resets at midnight UTC.',
  week: 'Frees up as lookups age out of the last 7 days.',
  month: 'Resets on the 1st (UTC).',
};

export interface KeyResolver {
  acquire(service: ServiceId): Promise<KeyGrant | KeySkip>;
  /** Peek without consuming quota: is any key available? */
  hasKey(service: ServiceId): boolean;
  skipped(): SkippedSource[];
}

export function createKeyResolver(options: KeyResolverOptions): KeyResolver {
  const { user } = options;
  const userKeys = new Map<ServiceId, string | null>();
  const skips = new Map<ServiceId, SkippedSource>();

  const userKey = (service: ServiceId) => {
    if (!user) return null;
    if (!userKeys.has(service)) userKeys.set(service, getUserKey(user.id, service));
    return userKeys.get(service) ?? null;
  };

  const serverKey = (service: ServiceId) =>
    options.allowServerKeys ? process.env[getService(service)!.envVar]?.trim() || null : null;

  const skip = (service: ServiceId, reason: string): KeySkip => {
    const name = getService(service)!.name;
    if (!skips.has(service)) skips.set(service, { service, name, reason });
    return { ok: false, service, reason };
  };

  return {
    hasKey: (service) => !options.freeSourcesOnly && !!(userKey(service) ?? serverKey(service)),

    async acquire(service) {
      const info = getService(service)!;
      if (options.freeSourcesOnly) return skip(service, 'Free sources only (bulk option).');
      let key = userKey(service);
      let source: KeySource = 'user';
      if (!key) {
        key = serverKey(service);
        source = 'server';
      }
      if (!key) {
        if (!user) return skip(service, `No ${info.name} key. Log in and add one in Settings.`);
        if (!options.allowServerKeys && process.env[info.envVar]) {
          return skip(service, `Bulk mode uses your own keys. Add your ${info.name} key in Settings.`);
        }
        return skip(service, `No ${info.name} key on your account. Add it in Settings.`);
      }

      if (source === 'user' && user && info.quota) {
        const used = usedInPeriod(user.id, service, 'user', info.quota.period);
        if (used >= info.quota.limit) {
          const period = { day: 'Daily', week: 'Weekly', month: 'Monthly' }[info.quota.period];
          return skip(service, `${period} quota used (${used} / ${info.quota.limit}). ${RESETS[info.quota.period]}`);
        }
        const cap = info.quota.dailyCap;
        if (cap && info.quota.period !== 'day') {
          const today = usedInPeriod(user.id, service, 'user', 'day');
          if (today >= cap) return skip(service, `Daily cap used (${today} / ${cap}). ${RESETS.day}`);
        }
      }

      if (info.perMinute) {
        const bucket = source === 'user' ? `user:${user!.id}:${service}` : `server:${service}`;
        const waitSec = await takeSlot(bucket, info.perMinute, options.maxRateWaitMs);
        if (waitSec > 0) {
          return skip(service, `${info.name} allows ${info.perMinute} lookups a minute. Try again in ${waitSec} s.`);
        }
      }

      if (user) recordUsage(user.id, service, source);
      return { ok: true, service, key, source };
    },

    skipped: () => Array.from(skips.values()),
  };
}
