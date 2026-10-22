import PageChrome from '@/components/chrome/PageChrome';
import { MarkBleed } from '@/components/decor';
import { requireAdmin } from '@/lib/server/auth/session';
import { listUsersForAdmin } from '@/lib/server/auth/users';
import { BULK_MAX_TARGETS, NEW_ACCOUNT_BULK_TARGETS } from '@/lib/bulk-input';
import AdminClient, { type AdminRowView } from './AdminClient';

export const dynamic = 'force-dynamic';
export const metadata = {
  title: 'Admin · OSINT Analyzer',
  description: 'Manage accounts: bulk limits, disabling and deleting.',
};

const DAY_MS = 24 * 60 * 60 * 1000;

function dateLabel(iso: string): string {
  // SQLite's created_at has no zone marker in old rows; both forms are UTC
  const date = new Date(iso.endsWith('Z') ? iso : `${iso.replace(' ', 'T')}Z`);
  return date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
}

function agoLabel(iso: string | null, now: number): string {
  if (!iso) return 'Not yet';
  const ms = now - new Date(iso).getTime();
  if (ms < 10 * 60 * 1000) return 'Just now';
  if (ms < DAY_MS) return `${Math.round(ms / 3_600_000) || 1} h ago`;
  if (ms < 30 * DAY_MS) return `${Math.round(ms / DAY_MS)} d ago`;
  return dateLabel(iso);
}

export default function AdminPage() {
  const me = requireAdmin('/admin');
  const now = Date.now();
  const users = listUsersForAdmin();
  const rows: AdminRowView[] = users.map((u) => ({
    ...u,
    createdLabel: dateLabel(u.createdAt),
    activeLabel: agoLabel(u.lastActiveAt, now),
  }));
  const activeWeek = users.filter((u) => u.lastActiveAt && now - new Date(u.lastActiveAt).getTime() < 7 * DAY_MS).length;
  const lookups = users.reduce((sum, u) => sum + u.lookups, 0);

  return (
    <PageChrome>
      <section aria-label="Top" className="oa-dots relative overflow-hidden border-b border-line">
        <MarkBleed size={340} style={{ right: -60, top: -90 }} />
        <div className="oa-wrap relative flex flex-col gap-2 pb-8 pt-10">
          <h1 className="oa-display text-[30px] leading-[1.1]">Accounts</h1>
          <p className="m-0 max-w-[64ch] text-muted">
            Anyone can sign up. New accounts can queue {NEW_ACCOUNT_BULK_TARGETS} targets per bulk job; raise that here (up to{' '}
            {BULK_MAX_TARGETS}) for people you trust. Disabling signs an account out and stops its jobs; deleting removes its keys,
            jobs and history.
          </p>
          <p className="m-0 font-mono text-[13px] text-muted">
            {users.length} account{users.length === 1 ? '' : 's'} · {activeWeek} active in the last 7 days · {lookups} lookups run
          </p>
        </div>
      </section>
      <AdminClient rows={rows} meId={me.id} defaultCap={NEW_ACCOUNT_BULK_TARGETS} maxCap={BULK_MAX_TARGETS} />
    </PageChrome>
  );
}
