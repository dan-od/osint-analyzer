import PageChrome from '@/components/chrome/PageChrome';
import { MarkBleed } from '@/components/decor';
import { PASSWORD_MIN_LENGTH } from '@/lib/server/auth/password';
import AuthCard, { type AuthTab } from './AuthCard';

/** /login and /signup: one card, two tabs */
export default function AuthPage({ tab, next }: { tab: AuthTab; next: string | null }) {
  return (
    <PageChrome header="minimal">
      <div className="oa-dots relative flex flex-auto items-center justify-center overflow-hidden px-5 py-14">
        <MarkBleed size={340} style={{ right: -60, top: -90 }} />
        <AuthCard
          initialTab={tab}
          next={next}
          signupsOpen={!!process.env.INVITE_CODE?.trim()}
          minPasswordLength={PASSWORD_MIN_LENGTH}
        />
      </div>
    </PageChrome>
  );
}
