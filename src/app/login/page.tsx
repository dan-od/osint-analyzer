import { redirect } from 'next/navigation';
import AuthPage from '@/components/auth/AuthPage';
import { getCurrentUser } from '@/lib/server/auth/session';
import { safeRedirectPath } from '@/lib/validation';

export const dynamic = 'force-dynamic';
export const metadata = {
  title: 'Log in · OSINT Analyzer',
  description: 'Log in with Google, GitHub or your email and password.',
};

export default function LoginPage({ searchParams }: { searchParams: { next?: string; error?: string } }) {
  if (getCurrentUser()) redirect(safeRedirectPath(searchParams.next, '/'));
  return <AuthPage tab="login" next={searchParams.next ?? null} error={searchParams.error} />;
}
