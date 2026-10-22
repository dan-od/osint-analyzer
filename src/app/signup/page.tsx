import { redirect } from 'next/navigation';
import AuthPage from '@/components/auth/AuthPage';
import { getCurrentUser } from '@/lib/server/auth/session';

export const dynamic = 'force-dynamic';
export const metadata = {
  title: 'Create account · OSINT Analyzer',
  description: 'Create a free account for IP checks, bulk jobs and your own API keys.',
};

export default function SignupPage({ searchParams }: { searchParams: { error?: string } }) {
  if (getCurrentUser()) redirect('/');
  return <AuthPage tab="signup" next={null} error={searchParams.error} />;
}
