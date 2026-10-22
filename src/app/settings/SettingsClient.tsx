'use client';

import KeyRow, { KEY_GRID } from '@/components/settings/KeyRow';
import AccountSection from '@/components/settings/AccountSection';
import SignInMethods, { type SignInMethodsProps } from '@/components/settings/SignInMethods';
import DeleteAccount from '@/components/settings/DeleteAccount';
import { FormMessage } from '@/components/auth/AuthCard';
import { useApiKeys } from '@/hooks/useApiKeys';
import { SERVICES } from '@/lib/services';
import type { PublicUser } from '@/types/account';

export default function SettingsClient({
  user,
  minPasswordLength,
  pendingEmail,
  signIn,
}: {
  user: PublicUser;
  minPasswordLength: number;
  pendingEmail: string | null;
  signIn: SignInMethodsProps;
}) {
  const { overview, loadError, rowState, saveKey, removeKey } = useApiKeys();
  const setCount = overview?.keys.filter((k) => k.maskedKey).length ?? 0;

  return (
    <div className="oa-wrap flex flex-col gap-9 pb-12 pt-7">
      <section aria-label="API keys" className="flex flex-col">
        <div className="mb-1 flex flex-wrap items-baseline gap-x-4 gap-y-2">
          <h2 className="m-0 text-[18px] font-semibold">API keys</h2>
          <span className="text-[14px] text-muted">
            {overview ? `${setCount} of ${SERVICES.length} set. ` : ''}Sources without a key are skipped, never faked.
          </span>
        </div>

        {loadError && <FormMessage>{loadError}</FormMessage>}
        {overview && !overview.encryptionReady && (
          <div className="my-3">
            <FormMessage>Saving keys is turned off: the server needs KEY_ENCRYPTION_SECRET (32+ characters).</FormMessage>
          </div>
        )}

        <div className={`oa-hide-sm ${KEY_GRID} border-b border-line py-[10px] text-[13px] text-muted`}>
          <span>Service</span>
          <span>Free tier and where to get it</span>
          <span>Status</span>
          <span>Key</span>
        </div>

        {!overview && !loadError && <p className="py-4 text-muted">Loading…</p>}
        {overview &&
          SERVICES.map((service) => {
            const status = overview.keys.find((k) => k.service === service.id);
            if (!status) return null;
            const { pending, error } = rowState(service.id);
            return (
              <KeyRow
                key={service.id}
                service={service}
                status={status}
                pending={pending}
                error={error}
                disabled={!overview.encryptionReady}
                onSave={(key) => saveKey(service.id, key)}
                onDelete={() => removeKey(service.id)}
              />
            );
          })}
        <p className="m-0 mt-[10px] text-[13px] text-skip">
          Links were correct when this page was written; if one lands somewhere odd, tell Daniel.
        </p>
      </section>

      <AccountSection user={user} minPasswordLength={minPasswordLength} hasPassword={signIn.hasPassword} pendingEmail={pendingEmail} />
      <SignInMethods {...signIn} />
      <DeleteAccount email={user.email} />
    </div>
  );
}
