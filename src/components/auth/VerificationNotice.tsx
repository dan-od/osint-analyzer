'use client';

import { useState } from 'react';
import { apiRequest } from '@/lib/client/http';

export type Delivery = 'email' | 'console' | 'failed';

/** What happened to the confirmation email, in words */
export function deliveryText(delivery: Delivery, email: string): string {
  if (delivery === 'email') return `We sent a confirmation link to ${email}. It works once and expires in 24 hours.`;
  if (delivery === 'console') {
    return 'Email isn’t set up on this server, so no email was sent. The confirmation link was written to the server log instead; ask the administrator for it.';
  }
  return 'The confirmation email couldn’t be sent. Try sending a new link in a few minutes.';
}

/** "Check your inbox" panel with a rate-limited resend button */
export default function VerificationNotice({ email, delivery: initial }: { email: string; delivery: Delivery | null }) {
  const [delivery, setDelivery] = useState<Delivery | null>(initial);
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const resend = async () => {
    setPending(true);
    setMessage(null);
    try {
      const data = await apiRequest<{ delivery: Delivery }>('/api/auth/resend-verification', {
        method: 'POST',
        body: JSON.stringify({ email }),
      });
      setDelivery(data.delivery);
      setMessage(data.delivery === 'failed' ? null : 'A new link is on its way. Earlier links no longer work.');
    } catch (e) {
      setMessage(e instanceof Error ? e.message : 'That didn’t work');
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="flex flex-col gap-3 rounded border border-line-strong border-l-[3px] border-l-accent bg-ground px-4 py-3 text-[14px] text-ink">
      <p className="m-0 font-semibold">Confirm your email to finish</p>
      {delivery && (
        <p className="m-0 text-ink-body" role="status">
          {deliveryText(delivery, email)}
        </p>
      )}
      <p className="m-0 text-muted">You can log in once the address is confirmed.</p>
      <div className="flex flex-wrap items-center gap-3">
        <button type="button" className="oa-btn h-9 px-3 text-[13px]" disabled={pending} onClick={() => void resend()}>
          {pending ? 'Sending…' : 'Send a new link'}
        </button>
        {message && (
          <span role="status" className="text-[13px] text-muted">
            {message}
          </span>
        )}
      </div>
    </div>
  );
}
