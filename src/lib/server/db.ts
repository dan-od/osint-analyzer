// SQLite access (server only). One connection per process, reused across
// hot reloads in development via globalThis.
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { BULK_MAX_TARGETS } from '@/lib/bulk-input';
import { schedulePruning } from './prune';

const SCHEMA = `
-- Auth.js tables (users, accounts, sessions, verification_tokens); see
-- prisma/schema.prisma for how the adapter maps onto them
CREATE TABLE IF NOT EXISTS users (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  name           TEXT NOT NULL,
  email          TEXT NOT NULL COLLATE NOCASE, -- unique among confirmed accounts (index below)
  email_verified DATETIME,
  image          TEXT,
  password_hash  TEXT,                       -- NULL: signs in with Google/GitHub only
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  role           TEXT NOT NULL DEFAULT 'user', -- 'user' | 'admin'
  disabled       INTEGER NOT NULL DEFAULT 0,
  bulk_cap       INTEGER,                    -- NULL: the new-account default
  last_active_at INTEGER,
  lookups        INTEGER NOT NULL DEFAULT 0
);

-- One row per linked Google/GitHub identity. OAuth tokens are not kept.
CREATE TABLE IF NOT EXISTS accounts (
  id                  TEXT PRIMARY KEY,
  user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type                TEXT NOT NULL,
  provider            TEXT NOT NULL,
  provider_account_id TEXT NOT NULL,
  refresh_token       TEXT,
  access_token        TEXT,
  expires_at          INTEGER,
  token_type          TEXT,
  scope               TEXT,
  id_token            TEXT,
  session_state       TEXT,
  created_at          INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000),
  UNIQUE (provider, provider_account_id)
);
CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id);

CREATE TABLE IF NOT EXISTS verification_tokens (
  identifier TEXT NOT NULL,
  token      TEXT NOT NULL,
  expires    DATETIME NOT NULL,
  UNIQUE (identifier, token)
);

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

export function resolveDbPath(): string {
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
  ['users', 'role', "TEXT NOT NULL DEFAULT 'user'"],     // 'user' | 'admin'
  ['users', 'disabled', 'INTEGER NOT NULL DEFAULT 0'],
  ['users', 'bulk_cap', 'INTEGER'],                       // NULL: the new-account default
  ['users', 'last_active_at', 'INTEGER'],
  ['users', 'lookups', 'INTEGER NOT NULL DEFAULT 0'],
  ['users', 'email_verified', 'DATETIME'],
  ['users', 'image', 'TEXT'],
  // When a confirmation link was used, so a second click says "already used"
  ['verification_tokens', 'used_at', 'INTEGER'],
  // Wrong passwords typed on the confirm page; the link locks at VERIFY_MAX_ATTEMPTS
  ['verification_tokens', 'failed_attempts', 'INTEGER NOT NULL DEFAULT 0'],
];

const SESSIONS_TABLE = `
CREATE TABLE sessions (
  id            TEXT PRIMARY KEY,
  session_token TEXT NOT NULL UNIQUE,        -- sha256 of the cookie value
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires       INTEGER NOT NULL,            -- ms since epoch
  created_at    INTEGER NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
`;

const USER_COLUMNS = [
  'id', 'name', 'email', 'email_verified', 'image', 'password_hash', 'created_at',
  'role', 'disabled', 'bulk_cap', 'last_active_at', 'lookups',
];

/**
 * Moves a pre-Auth.js database onto the Auth.js schema:
 * - users: password_hash becomes optional (SSO-only accounts). SQLite can't
 *   drop NOT NULL in place, so the table is rebuilt with every id kept as
 *   it was, which keeps api_keys, bulk_jobs etc. pointing at the same user.
 * - sessions: replaced by the Auth.js shape. Old sessions are dropped, so
 *   everyone logs in once more.
 */
function migrateToAuthJs(db: Database.Database): void {
  const userCols = db.prepare('PRAGMA table_info(users)').all() as { name: string; notnull: number }[];
  const passwordRequired = userCols.find((c) => c.name === 'password_hash')?.notnull === 1;
  // Email used to be UNIQUE on the column; now only confirmed accounts must be unique
  const usersSql = (db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'").get() as { sql: string }).sql;
  const emailColumnUnique = /email\s+TEXT\s+NOT\s+NULL\s+UNIQUE/i.test(usersSql);
  const rebuildUsers = passwordRequired || emailColumnUnique;
  const sessionCols = db.prepare('PRAGMA table_info(sessions)').all() as { name: string }[];
  const oldSessions = sessionCols.length > 0 && !sessionCols.some((c) => c.name === 'session_token');
  if (!rebuildUsers && sessionCols.length > 0 && !oldSessions) return;

  // Foreign keys must be off while users is swapped, or dropping it would cascade
  db.pragma('foreign_keys = OFF');
  try {
    db.transaction(() => {
      if (oldSessions) db.exec('DROP TABLE sessions');
      if (rebuildUsers) {
        // Same definition as SCHEMA's users table, under a temporary name
        const start = SCHEMA.indexOf('CREATE TABLE IF NOT EXISTS users (');
        const definition = SCHEMA.slice(start, SCHEMA.indexOf('\n);', start) + 3);
        db.exec(definition.replace('CREATE TABLE IF NOT EXISTS users (', 'CREATE TABLE users_new ('));
        const cols = USER_COLUMNS.join(', ');
        db.exec(`INSERT INTO users_new (${cols}) SELECT ${cols} FROM users`);
        db.exec('DROP TABLE users');
        db.exec('ALTER TABLE users_new RENAME TO users');
      }
      if (db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sessions'").get() === undefined) {
        db.exec(SESSIONS_TABLE);
      }
      const broken = db.pragma('foreign_key_check') as unknown[];
      if (broken.length > 0) throw new Error(`Auth.js migration left ${broken.length} broken foreign keys`);
    })();
  } finally {
    db.pragma('foreign_keys = ON');
  }
}

function migrate(db: Database.Database): void {
  const added = new Set<string>();
  for (const [table, column, definition] of ADDED_COLUMNS) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
    if (!columns.some((c) => c.name === column)) {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
      added.add(`${table}.${column}`);
    }
  }
  // Databases from the invite-only days: the first account is the admin, and
  // the invited accounts keep the full bulk limit they already had
  if (added.has('users.role')) db.exec("UPDATE users SET role = 'admin' WHERE id = (SELECT MIN(id) FROM users)");
  if (added.has('users.bulk_cap')) db.prepare('UPDATE users SET bulk_cap = ?').run(BULK_MAX_TARGETS);
  migrateToAuthJs(db);

  // One confirmed account per address. An unconfirmed password signup can share
  // its address with a Google/GitHub account until it is confirmed (then they
  // merge). Created here, after the columns exist and after any users rebuild.
  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_verified ON users(email) WHERE email_verified IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  `);

  // One-off steps, tracked with SQLite's user_version
  const version = db.pragma('user_version', { simple: true }) as number;
  if (version < 1) {
    // Email verification starts now: accounts that already exist keep working.
    // (Integer ms, the format Prisma uses for DateTime in SQLite.)
    db.prepare('UPDATE users SET email_verified = ? WHERE email_verified IS NULL').run(Date.now());
    db.pragma('user_version = 1');
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
    schedulePruning(db);
    globalForDb.__osintDb = db;
  }
  return globalForDb.__osintDb;
}
