import { getDb } from '../db';
import { BULK_MAX_TARGETS, NEW_ACCOUNT_BULK_TARGETS } from '@/lib/bulk-input';
import type { AdminUserRow, PublicUser, UserRole } from '@/types/account';

interface UserRow {
  id: number;
  name: string;
  email: string;
  password_hash: string | null;
  email_verified: number | null;
  created_at: string;
  role: UserRole;
  disabled: number;
  bulk_cap: number | null;
  last_active_at: number | null;
  lookups: number;
}

/** Only write "last active" this often, not on every request */
const ACTIVE_WRITE_MS = 5 * 60 * 1000;

function toPublic(row: UserRow): PublicUser {
  const bulkCap = row.role === 'admin' ? BULK_MAX_TARGETS : Math.min(row.bulk_cap ?? NEW_ACCOUNT_BULK_TARGETS, BULK_MAX_TARGETS);
  return { id: row.id, name: row.name, email: row.email, createdAt: row.created_at, role: row.role, bulkCap };
}

export type UserWithSecrets = PublicUser & { passwordHash: string | null; disabled: boolean; emailVerified: boolean };

function withSecrets(row: UserRow): UserWithSecrets {
  return { ...toPublic(row), passwordHash: row.password_hash, disabled: !!row.disabled, emailVerified: row.email_verified != null };
}

/**
 * Every account with this address, confirmed first. There can be two: a
 * confirmed (e.g. Google) account and an unconfirmed password signup, until
 * the signup is confirmed and merges in. Includes disabled accounts.
 */
export function findUsersByEmail(email: string): UserWithSecrets[] {
  const rows = getDb()
    .prepare('SELECT * FROM users WHERE email = ? ORDER BY email_verified IS NULL, id')
    .all(email) as UserRow[];
  return rows.map(withSecrets);
}

/** The confirmed account with this address, if any */
export function findConfirmedUserByEmail(email: string): UserWithSecrets | null {
  return findUsersByEmail(email).find((u) => u.emailVerified) ?? null;
}

/** The unconfirmed password signup for this address, if any */
export function findUnconfirmedSignup(email: string): UserWithSecrets | null {
  return findUsersByEmail(email).find((u) => !u.emailVerified && u.passwordHash) ?? null;
}

/** Active accounts only: a disabled account has no sessions, keys or jobs that work */
export function findUserById(id: number): PublicUser | null {
  const row = getDb().prepare('SELECT * FROM users WHERE id = ? AND disabled = 0').get(id) as UserRow | undefined;
  return row ? toPublic(row) : null;
}

/**
 * The very first account becomes the admin (one statement, so two signups
 * can't both win). passwordHash is null for accounts made through Google/GitHub.
 */
export function createUser(name: string, email: string, passwordHash: string | null, emailVerified = false): PublicUser {
  const info = getDb()
    .prepare(
      `INSERT INTO users (name, email, password_hash, email_verified, role)
       SELECT ?, ?, ?, ?, CASE WHEN EXISTS (SELECT 1 FROM users) THEN 'user' ELSE 'admin' END`
    )
    .run(name, email, passwordHash, emailVerified ? Date.now() : null);
  return findUserById(Number(info.lastInsertRowid))!;
}

/**
 * Signing up again with an address that is still unconfirmed starts over:
 * new name and password, and the earlier link stops working when the new
 * one is made. Whoever controls the inbox decides which signup counts.
 */
export function restartUnverifiedSignup(id: number, name: string, passwordHash: string): void {
  getDb().prepare('UPDATE users SET name = ?, password_hash = ? WHERE id = ? AND email_verified IS NULL').run(name, passwordHash, id);
}

export function updateProfile(id: number, name: string, email: string): PublicUser {
  getDb().prepare('UPDATE users SET name = ?, email = ? WHERE id = ?').run(name, email, id);
  return findUserById(id)!;
}

export function getPasswordHash(id: number): string | null {
  const row = getDb().prepare('SELECT password_hash FROM users WHERE id = ?').get(id) as { password_hash: string } | undefined;
  return row?.password_hash ?? null;
}

export function setPasswordHash(id: number, hash: string): void {
  getDb().prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id);
}

/** Clears the password; the account then signs in through a linked provider only */
export function removePassword(id: number): void {
  getDb().prepare('UPDATE users SET password_hash = NULL WHERE id = ?').run(id);
}

/** Account status regardless of `disabled`, for sign-in checks */
export function userStatus(id: number): { disabled: boolean } | null {
  const row = getDb().prepare('SELECT disabled FROM users WHERE id = ?').get(id) as { disabled: number } | undefined;
  return row ? { disabled: !!row.disabled } : null;
}

/** The confirmed account's id for this address; unconfirmed signups never count */
export function userIdByEmail(email: string): number | null {
  const row = getDb().prepare('SELECT id FROM users WHERE email = ? AND email_verified IS NOT NULL').get(email) as { id: number } | undefined;
  return row?.id ?? null;
}

export interface LinkedAccount {
  provider: string;
  linkedAt: string;
}

export function linkedAccounts(userId: number): LinkedAccount[] {
  const rows = getDb()
    .prepare('SELECT provider, created_at FROM accounts WHERE user_id = ? ORDER BY created_at')
    .all(userId) as { provider: string; created_at: number }[];
  return rows.map((r) => ({ provider: r.provider, linkedAt: new Date(r.created_at).toISOString() }));
}

export function userIdForAccount(provider: string, providerAccountId: string): number | null {
  const row = getDb()
    .prepare('SELECT user_id FROM accounts WHERE provider = ? AND provider_account_id = ?')
    .get(provider, providerAccountId) as { user_id: number } | undefined;
  return row?.user_id ?? null;
}

/** How the account can sign in: its password (if any) plus each linked provider */
export function signInMethodCount(userId: number): number {
  return (getPasswordHash(userId) ? 1 : 0) + linkedAccounts(userId).length;
}

export function unlinkProvider(userId: number, provider: string): boolean {
  return getDb().prepare('DELETE FROM accounts WHERE user_id = ? AND provider = ?').run(userId, provider).changes > 0;
}

export function touchLastActive(id: number): void {
  const now = Date.now();
  getDb()
    .prepare('UPDATE users SET last_active_at = ? WHERE id = ? AND (last_active_at IS NULL OR last_active_at < ?)')
    .run(now, id, now - ACTIVE_WRITE_MS);
}

/** Lookups an account has run (single checks and bulk items that weren't cached) */
export function countLookup(id: number): void {
  getDb().prepare('UPDATE users SET lookups = lookups + 1 WHERE id = ?').run(id);
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

export function listUsersForAdmin(): AdminUserRow[] {
  const rows = getDb().prepare('SELECT * FROM users ORDER BY created_at DESC, id DESC').all() as UserRow[];
  return rows.map((row) => ({
    ...toPublic(row),
    disabled: !!row.disabled,
    lastActiveAt: row.last_active_at ? new Date(row.last_active_at).toISOString() : null,
    lookups: row.lookups,
    customBulkCap: row.bulk_cap,
    emailVerified: row.email_verified != null,
  }));
}

export function findAnyUserById(id: number): AdminUserRow | null {
  return listUsersForAdmin().find((u) => u.id === id) ?? null;
}

/** null puts the account back on the new-account default */
export function setBulkCap(id: number, cap: number | null): void {
  getDb().prepare('UPDATE users SET bulk_cap = ? WHERE id = ?').run(cap, id);
}

/** Disabling signs the account out everywhere and stops its bulk jobs */
export function setDisabled(id: number, disabled: boolean): void {
  const db = getDb();
  db.transaction(() => {
    db.prepare('UPDATE users SET disabled = ? WHERE id = ?').run(disabled ? 1 : 0, id);
    if (disabled) {
      db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
      db.prepare(
        "UPDATE bulk_jobs SET status = 'cancelled', updated_at = ? WHERE user_id = ? AND status IN ('queued', 'running', 'paused')"
      ).run(Date.now(), id);
      db.prepare(
        "UPDATE bulk_items SET status = 'cancelled' WHERE status = 'queued' AND job_id IN (SELECT id FROM bulk_jobs WHERE user_id = ? AND status = 'cancelled')"
      ).run(id);
    }
  })();
}

/** Sessions, keys, cache, recent checks and bulk jobs go with it (ON DELETE CASCADE) */
export function deleteUser(id: number): void {
  getDb().prepare('DELETE FROM users WHERE id = ?').run(id);
}
