import PageChrome from '@/components/chrome/PageChrome';
import { requireUser } from '@/lib/server/auth/session';
import BulkClient from './BulkClient';

export const dynamic = 'force-dynamic';
export const metadata = { title: 'Bulk check · OSINT Analyzer' };

export default function BulkPage({ searchParams }: { searchParams: { job?: string } }) {
  requireUser('/bulk');
  return (
    <PageChrome>
      <BulkClient initialJobId={searchParams.job ?? null} />
    </PageChrome>
  );
}
