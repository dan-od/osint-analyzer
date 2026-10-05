import { redirect } from 'next/navigation';
import AuthPage from '@/components/auth/AuthPage';
import { getCurrentUser } from '@/lib/server/auth/session';

export const dynamic = 'force-dynamic';
export const metadata = { title: 'Create account · OSINT Analyzer' };

export default function SignupPage() {
  if (getCurrentUser()) redirect('/');
  return <AuthPage tab="signup" next={null} />;
}
