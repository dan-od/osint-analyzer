import { getDb } from '../db';
import { decryptSecret, encryptSecret } from './crypto';
import type { ServiceId } from '@/lib/services';

const aadFor = (userId: number, service: ServiceId) => `user:${userId}|service:${service}`;

export function saveUserKey(userId: number, service: ServiceId, key: string): void {
  const ciphertext = encryptSecret(key, aadFor(userId, service));
  getDb()
    .prepare(
      `INSERT INTO api_keys (user_id, service, ciphertext, last4, updated_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(user_id, service) DO UPDATE SET ciphertext = excluded.ciphertext,
         last4 = excluded.last4, updated_at = excluded.updated_at`
    )
    .run(userId, service, ciphertext, key.slice(-4), Date.now());
}

export function deleteUserKey(userId: number, service: ServiceId): boolean {
  return getDb().prepare('DELETE FROM api_keys WHERE user_id = ? AND service = ?').run(userId, service).changes > 0;
}

/** Last four characters of each saved key; never the key itself. */
export function listUserKeyHints(userId: number): Map<ServiceId, { last4: string; updatedAt: number }> {
  const rows = getDb()
    .prepare('SELECT service, last4, updated_at FROM api_keys WHERE user_id = ?')
    .all(userId) as { service: ServiceId; last4: string; updated_at: number }[];
  return new Map(rows.map((r) => [r.service, { last4: r.last4, updatedAt: r.updated_at }]));
}

export function getUserKey(userId: number, service: ServiceId): string | null {
  const row = getDb()
    .prepare('SELECT ciphertext FROM api_keys WHERE user_id = ? AND service = ?')
    .get(userId, service) as { ciphertext: string } | undefined;
  if (!row) return null;
  try {
    return decryptSecret(row.ciphertext, aadFor(userId, service));
  } catch (error) {
    console.error(`Could not decrypt stored ${service} key for user ${userId}:`, (error as Error).message);
    return null;
  }
}
