import { getDb } from '../db';
import type { PublicUser } from '@/types/account';

interface UserRow {
  id: number;
  name: string;
  email: string;
  password_hash: string;
  created_at: string;
}

function toPublic(row: UserRow): PublicUser {
  return { id: row.id, name: row.name, email: row.email, createdAt: row.created_at };
}

export function findUserByEmail(email: string): (PublicUser & { passwordHash: string }) | null {
  const row = getDb()
    .prepare('SELECT * FROM users WHERE email = ?')
    .get(email) as UserRow | undefined;
  return row ? { ...toPublic(row), passwordHash: row.password_hash } : null;
}

export function findUserById(id: number): PublicUser | null {
  const row = getDb().prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
  return row ? toPublic(row) : null;
}

export function emailExists(email: string): boolean {
  return !!getDb().prepare('SELECT 1 FROM users WHERE email = ?').get(email);
}

export function createUser(name: string, email: string, passwordHash: string): PublicUser {
  const info = getDb()
    .prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)')
    .run(name, email, passwordHash);
  return findUserById(Number(info.lastInsertRowid))!;
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
