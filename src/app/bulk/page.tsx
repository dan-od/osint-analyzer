import PageChrome from '@/components/chrome/PageChrome';
import { requireUser } from '@/lib/server/auth/session';
import BulkClient from './BulkClient';

export const dynamic = 'force-dynamic';
export const metadata = {
  title: 'Bulk check · OSINT Analyzer',
  description: 'Check a list of IPs and domains at once, from a paste or a CSV, and export the verdicts.',
};

export default function BulkPage({ searchParams }: { searchParams: { job?: string } }) {
  const user = requireUser('/bulk');
  return (
    <PageChrome>
      <BulkClient initialJobId={searchParams.job ?? null} maxTargets={user.bulkCap} />
    </PageChrome>
  );
}
