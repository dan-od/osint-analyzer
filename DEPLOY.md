# Deploying OSINT Analyzer

Every push to `main` (or **Actions → Deploy OSINT Analyzer → Run workflow**) runs
`.github/workflows/deploy.yml`:

1. `npm ci`, `npm test` and `npm run build` on the runner. A commit whose tests fail, or that
   doesn't build, stops here.
2. The runner joins the tailnet (Tailscale OAuth, `tag:ci`).
3. `rsync --delete` of the repo to `/opt/docker-homelab/sites/osint/`
   (without `node_modules`, `.next`, `.git`, `.env*`, `data`, `design`).
4. On the server, in `/opt/docker-homelab`, in this order:
   1. `docker compose config -q` (bad YAML stops here)
   2. The image the running container uses is tagged `osint-analyzer:previous`, before the
      build moves `osint-analyzer:latest`. Skipped when nothing is running. If the image
      can't be tagged, the job logs a warning and carries on; `:previous` then stays
      as it was, and rolling back that deploy means `git revert` and redeploy.
   3. `docker compose build osint` (the old container keeps serving)
   4. **Backup** with the newly built image, in a one-off container that has the service's
      volume and env: `docker compose run --rm --no-deps -T osint node - < sites/osint/scripts/backup-db.cjs`.
      It writes `data/backups/osint-<UTC time>.db` and keeps the newest 5.
      - No database yet (first deploy): it logs "no database yet, nothing to back up" and the deploy carries on.
      - A database that can't be backed up: the deploy **stops here**. Nothing is swapped and the old container keeps running.
   5. `docker compose up -d --no-deps osint`
   6. Wait up to 60 s for `http://127.0.0.1:3000/api/health` inside the container. On
      failure the job prints the last 50 log lines and fails. Then `docker image prune -f`
      and `docker compose ps osint`.

Only the `osint` service is ever built or restarted. Nothing runs `docker compose down`.
Two deploys never overlap (`concurrency: deploy-osint`); a newer one waits.

## One-time setup

### GitHub secrets

| Secret | What |
|---|---|
| `TS_OAUTH_CLIENT_ID`, `TS_OAUTH_SECRET` | A Tailscale OAuth client with the **Auth Keys (write)** scope that may assign `tag:ci` |
| `DEPLOY_USER` | The SSH user on the homelab; must be in the `docker` group and own `/opt/docker-homelab/sites/osint` |
| `HOMELAB_HOST` | The homelab's tailnet name or 100.x address |

### Tailscale policy

```jsonc
"tagOwners": { "tag:ci": ["autogroup:admin"] },
// The workflow has no SSH key: it relies on Tailscale SSH
"ssh": [
  { "action": "accept", "src": ["tag:ci"], "dst": ["<homelab tag or host>"], "users": ["<DEPLOY_USER>"] }
]
```

### Environment file on the server

Create `/opt/docker-homelab/sites/osint/.env.production`. rsync never sends or deletes
`.env*` files, and `.dockerignore` keeps them out of the image. Every variable is described in
`.env.example`; these are the ones production needs:

```ini
# Required
KEY_ENCRYPTION_SECRET=   # 32+ chars; changing it makes saved API keys unreadable
AUTH_SECRET=             # npx auth secret
AUTH_URL=https://osint.okoro.me

# Email confirmation (Resend). Without the key, links go to the container log.
RESEND_API_KEY=
MAIL_LINK_BASE=https://osint.okoro.me
# Optional; these are the defaults. The From domain must be verified in Resend.
MAIL_FROM="OSINT Analyzer <osint@mail.protechnetworks.org>"
MAIL_REPLY_TO=support@protechnetworks.org

# Sign-in buttons appear only when both values are set
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_ID=
GITHUB_SECRET=

# Look-alike detection: lets the server generate a fresh Tranco list every few days.
# Without it, the bundled list is used until its data is 7 days old, then the check is skipped.
TRANCO_API_EMAIL=
TRANCO_API_KEY=

# Optional server fallback keys for sources (VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, ...)
```

OAuth redirect URIs to register:
`https://osint.okoro.me/api/auth/callback/google` and `https://osint.okoro.me/api/auth/callback/github`.

### Compose service

In `/opt/docker-homelab/docker-compose.yml`:

```yaml
services:
  osint:
    build: ./sites/osint
    image: osint-analyzer:latest          # a fixed name makes rollback a one-liner (see below)
    container_name: osint-analyzer
    restart: unless-stopped
    env_file: ./sites/osint/.env.production
    environment:
      NODE_ENV: production
      DATABASE_URL: file:/app/data/osint.db
    volumes:
      - osint-data:/app/data             # database, backups/, blocklist feed cache
    expose:
      - "3000"
    # networks: [the network nginx/cloudflared use to reach it]

volumes:
  osint-data:
```

`/app/data` holds the SQLite database (`osint.db`), the pre-deploy backups (`backups/`, the
newest 5) and the downloaded blocklist feeds. Never put it on the container's own filesystem.

## Database migrations

There are no Prisma migrations (Prisma only reads the Auth.js tables). Schema changes live
in `src/lib/server/db.ts` and run **when the app first opens the database after starting**;
the deploy's health check triggers that. They only move forward: a step that ran stays
applied, whatever code runs afterwards.

So **rolling back the code does not roll back the database.** Older code copes with columns
it doesn't know about, but not with tables whose shape changed. In particular, any version
from before the Auth.js switch can't read the new `sessions` and `users` tables. Rolling back
across a schema change means restoring the backup taken before that deploy, which loses
anything written since.

## Rolling back

`osint-analyzer:previous` is always the image that was running before the latest deploy.
Point the name the service runs under back at it, then recreate the container. With
`image: osint-analyzer:latest` on the service that name is `osint-analyzer:latest`; without an
`image:` line compose calls it `<project>-osint` (here probably `docker-homelab-osint:latest`;
`docker images | grep osint` shows it).

**Code only** (the database didn't change, or the old code can read it):

```sh
cd /opt/docker-homelab
docker tag osint-analyzer:previous osint-analyzer:latest
docker compose up -d --no-deps osint
```

Then `git revert` the bad commit and push, so the next deploy doesn't bring it back.

**Code and database:**

```sh
cd /opt/docker-homelab
VOL=$(docker volume ls -q | grep 'osint-data$')         # e.g. docker-homelab_osint-data
docker run --rm -v "$VOL":/data alpine ls -l /data/backups    # pick the backup from before the bad deploy
docker compose stop osint
docker run --rm -v "$VOL":/data alpine sh -c \
  'cp /data/osint.db /data/osint.db.before-restore && cp /data/backups/osint-<timestamp>.db /data/osint.db && rm -f /data/osint.db-wal /data/osint.db-shm'
docker tag osint-analyzer:previous osint-analyzer:latest
docker compose up -d --no-deps osint
```

Backups are named by UTC time (`osint-2026-10-22T16-45-35-933Z.db`) and taken just before each
deploy's swap, so the newest one before the bad deploy's time is the state it started from.

### The first deploy

The container running before the first deploy is a pre-accounts build (Node 18, no SQLite).
That deploy finds no database, so no backup is taken; the new container creates `osint.db`
when it starts (the health check triggers it). `:previous` is that old pre-accounts image.
Rolling back to it is possible, but it has no accounts at all.

## Checking a deploy by hand

```sh
cd /opt/docker-homelab
docker compose exec -T osint wget -qO- http://127.0.0.1:3000/api/health   # {"ok":true}
docker compose logs --tail 50 osint
```
