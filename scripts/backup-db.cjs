// Consistent snapshot of the SQLite database, taken inside the running
// container before a deploy (SQLite's online backup, safe while the app
// writes). Kept next to the database in data/backups/, newest 5 only.
//
//   docker compose exec -T osint node - < sites/osint/scripts/backup-db.cjs
//
// Read from stdin so it also runs in an older image that doesn't have it.
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const KEEP = 5;
const url = process.env.DATABASE_URL || 'file:./data/osint.db';
const file = path.resolve('/app', url.replace(/^file:/, ''));

if (!fs.existsSync(file)) {
  console.log(`backup: no database at ${file} yet, nothing to back up`);
  process.exit(0);
}

const dir = path.join(path.dirname(file), 'backups');
fs.mkdirSync(dir, { recursive: true });
const target = path.join(dir, `osint-${new Date().toISOString().replace(/[:.]/g, '-')}.db`);

new Database(file, { readonly: true })
  .backup(target)
  .then(() => {
    const old = fs.readdirSync(dir).filter((f) => /^osint-.*\.db$/.test(f)).sort().reverse().slice(KEEP);
    for (const f of old) fs.unlinkSync(path.join(dir, f));
    console.log(`backup: ${target} (${fs.statSync(target).size} bytes)${old.length ? `, removed ${old.length} older` : ''}`);
  })
  .catch((error) => {
    console.error('backup failed:', error.message);
    process.exit(1);
  });
