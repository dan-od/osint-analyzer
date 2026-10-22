import PageChrome from '@/components/chrome/PageChrome';
import { MarkBleed } from '@/components/decor';
import { PASSWORD_MIN_LENGTH } from '@/lib/server/auth/password';
import { AUTH_ERRORS, AUTH_ERROR_FALLBACK, enabledOAuthProviders } from '@/lib/server/auth/providers';
import AuthCard, { type AuthTab } from './AuthCard';

/** /login and /signup: one card, two tabs */
export default function AuthPage({ tab, next, error }: { tab: AuthTab; next: string | null; error?: string }) {
  return (
    <PageChrome header="minimal">
      <div className="oa-dots relative flex flex-auto items-center justify-center overflow-hidden px-5 py-14">
        <MarkBleed size={340} style={{ right: -60, top: -90 }} />
        <AuthCard
          initialTab={tab}
          next={next}
          minPasswordLength={PASSWORD_MIN_LENGTH}
          providers={enabledOAuthProviders()}
          error={error ? AUTH_ERRORS[error] ?? AUTH_ERROR_FALLBACK : null}
        />
      </div>
    </PageChrome>
  );
}
