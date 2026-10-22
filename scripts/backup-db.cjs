// Consistent snapshot of the SQLite database before a deploy, using SQLite's
// online backup (safe while the live app writes). Runs in a one-off container
// of the newly built image with the data volume mounted:
//
//   docker compose run --rm --no-deps -T osint node - < sites/osint/scripts/backup-db.cjs
//
// Writes data/backups/osint-<UTC time>.db and keeps the newest 5.
// Exit 0: backed up, or no database yet (first deploy). Exit 1: a database
// exists but couldn't be backed up, so the deploy must stop.
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const KEEP = 5;
const url = process.env.DATABASE_URL || 'file:./data/osint.db';
const file = path.resolve('/app', url.replace(/^file:/, ''));

if (!fs.existsSync(file)) {
  console.log(`backup: no database yet, nothing to back up (${file})`);
  process.exit(0);
}

const dir = path.join(path.dirname(file), 'backups');
fs.mkdirSync(dir, { recursive: true });
const target = path.join(dir, `osint-${new Date().toISOString().replace(/[:.]/g, '-')}.db`);

let db;
try {
  db = new Database(file, { readonly: true, fileMustExist: true });
} catch (error) {
  console.error(`backup failed: could not open ${file}: ${error.message}`);
  process.exit(1);
}

db.backup(target)
  .then(() => {
    const old = fs.readdirSync(dir).filter((f) => /^osint-.*\.db$/.test(f)).sort().reverse().slice(KEEP);
    for (const f of old) fs.unlinkSync(path.join(dir, f));
    console.log(`backup: ${target} (${fs.statSync(target).size} bytes)${old.length ? `, removed ${old.length} older` : ''}`);
  })
  .catch((error) => {
    console.error('backup failed:', error.message);
    process.exit(1);
  });
