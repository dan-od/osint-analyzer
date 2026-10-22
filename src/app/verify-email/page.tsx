import Link from 'next/link';
import PageChrome from '@/components/chrome/PageChrome';
import { CornerTicks, MarkBleed } from '@/components/decor';
import { peekToken } from '@/lib/server/auth/verification';
import { getCurrentUser } from '@/lib/server/auth/session';
import { RETENTION } from '@/lib/retention';
import ConfirmEmail from './ConfirmEmail';
import ResendForm from './ResendForm';

export const dynamic = 'force-dynamic';
export const metadata = {
  title: 'Confirm your email · OSINT Analyzer',
  description: 'Confirm the email address for your OSINT Analyzer account.',
  robots: { index: false },
};

export default function VerifyEmailPage({ searchParams }: { searchParams: { token?: string } }) {
  const token = searchParams.token ?? '';
  const check = peekToken(token);
  const user = getCurrentUser();

  let title = 'Confirm your email';
  let body: React.ReactNode;
  if (check.ok && check.info.purpose === 'email-change' && user?.id !== check.info.userId) {
    // Email changes are confirmed from inside the account they belong to
    title = 'Log in to confirm';
    body = (
      <div className="flex flex-col gap-4">
        <p className="m-0 text-ink-body">
          This link moves an account to <span className="text-ink">{check.info.email}</span>. Log in to that account, then the
          change can be confirmed.
        </p>
        <Link href={`/login?next=${encodeURIComponent(`/verify-email?token=${token}`)}`} className="oa-btn-primary h-12 text-[16px]">
          Log in
        </Link>
      </div>
    );
  } else if (check.ok) {
    body = <ConfirmEmail token={token} purpose={check.info.purpose} email={check.info.email} />;
  } else if (check.reason === 'locked') {
    title = 'Link locked';
    body = (
      <div className="flex flex-col gap-4">
        <p className="m-0 text-ink-body" role="alert">
          The wrong password was entered too many times, so this link no longer works. Ask for a new one below.
        </p>
        <ResendForm />
      </div>
    );
  } else if (check.reason === 'used') {
    title = 'Link already used';
    body = (
      <div className="flex flex-col gap-4">
        <p className="m-0 text-ink-body" role="alert">
          This confirmation link has already been used, so the address is confirmed. Each link works once.
        </p>
        {user ? (
          <Link href="/" className="oa-btn-primary h-12 text-[16px]">Start checking</Link>
        ) : (
          <Link href="/login" className="oa-btn-primary h-12 text-[16px]">Log in</Link>
        )}
      </div>
    );
  } else if (check.reason === 'expired') {
    title = 'Link expired';
    body = (
      <div className="flex flex-col gap-4">
        <p className="m-0 text-ink-body" role="alert">
          Confirmation links expire after {RETENTION.verificationLinkHours} hours, and this one has. Ask for a new one below.
        </p>
        <ResendForm />
      </div>
    );
  } else {
    title = 'Link not valid';
    body = (
      <div className="flex flex-col gap-4">
        <p className="m-0 text-ink-body" role="alert">
          This link isn&apos;t valid. It may have been copied incompletely, or replaced by a newer link (only the latest one
          works). Ask for a new one below, or <Link href="/login">log in</Link> if you&apos;ve already confirmed.
        </p>
        <ResendForm />
      </div>
    );
  }

  return (
    <PageChrome header="minimal">
      <div className="oa-dots relative flex flex-auto items-center justify-center overflow-hidden px-5 py-14">
        <MarkBleed size={340} style={{ right: -60, top: -90 }} />
        <div className="relative box-border flex w-full max-w-[440px] flex-col gap-[18px] rounded border border-line bg-panel p-7 max-[420px]:p-5">
          <CornerTicks tone="accent" />
          <h1 className="oa-display text-[28px] leading-[1.1]">{title}</h1>
          {body}
        </div>
      </div>
    </PageChrome>
  );
}
