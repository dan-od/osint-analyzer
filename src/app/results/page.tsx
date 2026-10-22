import type { Metadata } from 'next';
import PageChrome from '@/components/chrome/PageChrome';
import ResultsClient from './ResultsClient';

export const dynamic = 'force-dynamic';

export function generateMetadata({ searchParams }: { searchParams: { q?: string } }): Metadata {
  return {
    title: searchParams.q ? `Results: ${searchParams.q} · OSINT Analyzer` : 'Results · OSINT Analyzer',
    description: 'A plain-words verdict for a link, email, phone number, IP address or wallet, with every source’s answer.',
  };
}

export default function ResultsPage() {
  return (
    <PageChrome>
      <ResultsClient />
    </PageChrome>
  );
}
