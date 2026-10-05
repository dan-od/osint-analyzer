// In-memory fixed-window attempt counter, used to slow down password guessing.
// Per process only, which is fine for a single Node server.

interface Window {
  count: number;
  resetAt: number;
}

const globalForLimits = globalThis as unknown as { __osintAttempts?: Map<string, Window> };
const windows = (globalForLimits.__osintAttempts ??= new Map());

export function hitLimit(
  key: string,
  limit: number,
  windowMs: number
): { ok: boolean; retryAfterSec: number } {
  const now = Date.now();
  let w = windows.get(key);
  if (!w || w.resetAt <= now) {
    w = { count: 0, resetAt: now + windowMs };
    windows.set(key, w);
  }
  w.count++;
  if (windows.size > 10_000) {
    windows.forEach((v, k) => {
      if (v.resetAt <= now) windows.delete(k);
    });
  }
  return { ok: w.count <= limit, retryAfterSec: Math.ceil((w.resetAt - now) / 1000) };
}
