// "/" is the public home for visitors and the dashboard once logged in
import PageChrome from '@/components/chrome/PageChrome';
import PublicHome from '@/components/home/PublicHome';
import Dashboard, { type DashboardData } from '@/components/home/Dashboard';
import { getCurrentUser } from '@/lib/server/auth/session';
import { listRecentChecks } from '@/lib/server/recent';
import { listJobs } from '@/lib/server/bulk/jobs';
import { keyStatusesFor } from '@/lib/server/keys/status';
import { feedStatus } from '@/lib/server/blocklists/feeds';
import { SERVICES } from '@/lib/services';
import type { PublicUser } from '@/types/account';

export const dynamic = 'force-dynamic';

const PERIOD_HINT = { day: '', week: 'this week', month: 'this month' };

function dashboardData(user: PublicUser): DashboardData {
  const keys = keyStatusesFor(user.id);
  const quotas: DashboardData['quotas'] = [];
  for (const status of keys) {
    const q = status.usage.quota;
    if (!status.maskedKey || !q) continue;
    const name = SERVICES.find((s) => s.id === status.service)!.name;
    // Monthly allowance with a daily cap (IPQualityScore): today's cap is what runs out first
    if (q.dailyCap) quotas.push({ name, period: 'today', used: q.dailyCap.used, limit: q.dailyCap.limit });
    else quotas.push({ name, period: PERIOD_HINT[q.period], used: q.used, limit: q.limit });
  }
  // Spamhaus DQS isn't "off" without a key: it falls back to the public mirror
  const missingServices = SERVICES.filter((s) => {
    if (s.id === 'spamhaus_dqs') return false;
    const k = keys.find((x) => x.service === s.id);
    return k && !k.maskedKey && !k.serverFallback;
  });
  const paid = missingServices.filter((s) => s.id === 'hibp').map((s) => s.name);
  const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;

  return {
    firstName: user.name.split(/\s+/)[0],
    recent: listRecentChecks(user.id),
    jobs: listJobs(user.id, 10)
      .filter((j) => new Date(j.createdAt).getTime() >= weekAgo)
      .map((j) => ({ id: j.id, name: j.name, total: j.total, flagged: j.flagged, status: j.status, createdAt: j.createdAt })),
    quotas,
    missing: { names: missingServices.map((s) => s.name), allFree: paid.length === 0, paid },
    feeds: feedStatus().map((f) => ({ name: f.name, entries: f.entries, updatedAt: f.updatedAt })),
  };
}

export default function Home() {
  const user = getCurrentUser();
  return <PageChrome>{user ? <Dashboard data={dashboardData(user)} /> : <PublicHome />}</PageChrome>;
}
