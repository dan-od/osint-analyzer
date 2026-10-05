// SQLite access (server only). One connection per process, reused across
// hot reloads in development via globalThis.
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,              -- sha256(token), the raw token only lives in the cookie
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS api_keys (
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  service     TEXT NOT NULL,
  ciphertext  TEXT NOT NULL,                 -- AES-256-GCM, see keys/crypto.ts
  last4       TEXT NOT NULL,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, service)
);

CREATE TABLE IF NOT EXISTS api_usage (
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  service     TEXT NOT NULL,
  key_source  TEXT NOT NULL,                 -- 'user' | 'server'
  day         TEXT NOT NULL,                 -- YYYY-MM-DD (UTC)
  count       INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, service, key_source, day)
);

CREATE TABLE IF NOT EXISTS lookup_cache (
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target      TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, target)
);

-- Targets only (no results), kept 7 days for the dashboard
CREATE TABLE IF NOT EXISTS recent_checks (
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target      TEXT NOT NULL,
  type        TEXT NOT NULL,
  checked_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, target)
);

CREATE TABLE IF NOT EXISTS bulk_jobs (
  id          TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status      TEXT NOT NULL,                 -- 'queued' | 'running' | 'paused' | 'done' | 'cancelled'
  total       INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bulk_jobs_user ON bulk_jobs(user_id, created_at);

CREATE TABLE IF NOT EXISTS bulk_items (
  job_id      TEXT NOT NULL REFERENCES bulk_jobs(id) ON DELETE CASCADE,
  idx         INTEGER NOT NULL,
  target      TEXT NOT NULL,
  type        TEXT NOT NULL,
  status      TEXT NOT NULL,                 -- 'queued' | 'running' | 'done' | 'error' | 'skipped' | 'cancelled'
  cached      INTEGER NOT NULL DEFAULT 0,
  result_json TEXT,
  error       TEXT,
  PRIMARY KEY (job_id, idx)
);
`;

function resolveDbPath(): string {
  const raw = process.env.DATABASE_URL?.trim() || 'file:./data/osint.db';
  const file = raw.startsWith('file:') ? raw.slice('file:'.length) : raw;
  return path.isAbsolute(file) ? file : path.join(process.cwd(), file);
}

// Columns added after the first release; CREATE TABLE IF NOT EXISTS won't add them
const ADDED_COLUMNS: [table: string, column: string, definition: string][] = [
  ['bulk_jobs', 'name', "TEXT NOT NULL DEFAULT 'Pasted list'"],
  ['bulk_jobs', 'options_json', "TEXT NOT NULL DEFAULT '{}'"],
  ['bulk_jobs', 'pasted', 'INTEGER NOT NULL DEFAULT 0'],
  ['bulk_items', 'risk_level', 'TEXT'],
  ['bulk_items', 'risk_score', 'INTEGER'],
];

function migrate(db: Database.Database): void {
  for (const [table, column, definition] of ADDED_COLUMNS) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
    if (!columns.some((c) => c.name === column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

const globalForDb = globalThis as unknown as { __osintDb?: Database.Database };

export function getDb(): Database.Database {
  if (!globalForDb.__osintDb) {
    const file = resolveDbPath();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const db = new Database(file);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    db.pragma('busy_timeout = 5000');
    db.exec(SCHEMA);
    migrate(db);
    globalForDb.__osintDb = db;
  }
  return globalForDb.__osintDb;
}
