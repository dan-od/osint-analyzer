import PageChrome from '@/components/chrome/PageChrome';
import { MarkBleed } from '@/components/decor';
import { requireUser } from '@/lib/server/auth/session';
import { PASSWORD_MIN_LENGTH } from '@/lib/server/auth/password';
import SettingsClient from './SettingsClient';

export const dynamic = 'force-dynamic';
export const metadata = { title: 'Settings · OSINT Analyzer' };

export default function SettingsPage() {
  const user = requireUser('/settings');
  return (
    <PageChrome>
      <section aria-label="Top" className="oa-dots relative overflow-hidden border-b border-line">
        <MarkBleed size={340} style={{ right: -60, top: -90 }} />
        <div className="oa-wrap relative flex flex-col gap-2 pb-8 pt-10">
          <h1 className="oa-display text-[30px] leading-[1.1]">Settings</h1>
          <p className="m-0 max-w-[64ch] text-muted">
            Your keys are encrypted on the server and only ever used for your own lookups. Each one is free; the links go
            straight to the sign-up and key pages so you are not hunting through menus.
          </p>
        </div>
      </section>
      <SettingsClient user={user} minPasswordLength={PASSWORD_MIN_LENGTH} />
    </PageChrome>
  );
}
