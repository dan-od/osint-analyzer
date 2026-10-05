// Sliding one-minute window per API key, for providers with per-minute caps
// (VirusTotal: 4/min). Buckets are keyed by key owner, so users never share.

const WINDOW_MS = 60_000;

const globalForBuckets = globalThis as unknown as { __osintBuckets?: Map<string, number[]> };
const buckets = (globalForBuckets.__osintBuckets ??= new Map());

function prune(stamps: number[], now: number): number[] {
  return stamps.filter((t) => now - t < WINDOW_MS);
}

/**
 * Takes a slot if one is free, otherwise waits up to maxWaitMs for one.
 * Returns 0 on success, or the seconds until a slot frees up.
 */
export async function takeSlot(bucket: string, perMinute: number, maxWaitMs: number): Promise<number> {
  const deadline = Date.now() + maxWaitMs;
  for (;;) {
    const now = Date.now();
    const stamps = prune(buckets.get(bucket) ?? [], now);
    if (stamps.length < perMinute) {
      stamps.push(now);
      buckets.set(bucket, stamps);
      return 0;
    }
    buckets.set(bucket, stamps);
    const waitMs = stamps[0] + WINDOW_MS - now + 50;
    if (now + waitMs > deadline) return Math.ceil(waitMs / 1000);
    await new Promise((r) => setTimeout(r, waitMs));
  }
}
