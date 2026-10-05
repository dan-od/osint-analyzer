import type { Metadata } from 'next';
import PageChrome from '@/components/chrome/PageChrome';
import ResultsClient from './ResultsClient';

export const dynamic = 'force-dynamic';

export function generateMetadata({ searchParams }: { searchParams: { q?: string } }): Metadata {
  return { title: searchParams.q ? `Results: ${searchParams.q} · OSINT Analyzer` : 'Results · OSINT Analyzer' };
}

export default function ResultsPage() {
  return (
    <PageChrome>
      <ResultsClient />
    </PageChrome>
  );
}
