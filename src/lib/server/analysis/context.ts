import type { ServiceId } from '@/lib/services';
import type { PublicUser } from '@/types/account';
import { createKeyResolver, type KeyResolver } from '../keys/resolver';
import { Progress, type ProgressListener } from './progress';

export interface AnalysisContext {
  user: PublicUser | null;
  mode: 'single' | 'bulk';
  keys: KeyResolver;
  progress: Progress;
}

export interface AnalysisOptions {
  /** Bulk option: skip every keyed source (saves the user's quotas) */
  freeSourcesOnly?: boolean;
  onEvent?: ProgressListener;
}

export function createAnalysisContext(
  user: PublicUser | null,
  mode: 'single' | 'bulk',
  options: AnalysisOptions = {}
): AnalysisContext {
  return {
    user,
    mode,
    keys: createKeyResolver({
      user,
      allowServerKeys: mode === 'single',
      // Bulk jobs queue behind per-minute limits; single lookups skip instead of hanging
      maxRateWaitMs: mode === 'bulk' ? 90_000 : 0,
      freeSourcesOnly: options.freeSourcesOnly ?? false,
    }),
    progress: new Progress(options.onEvent),
  };
}

/** Runs a keyed API call if a key is available; otherwise the resolver records the skip. */
export async function withKey<T>(
  ctx: AnalysisContext,
  service: ServiceId,
  call: (key: string) => Promise<T | null>
): Promise<T | null> {
  const grant = await ctx.keys.acquire(service);
  return grant.ok ? call(grant.key) : null;
}
