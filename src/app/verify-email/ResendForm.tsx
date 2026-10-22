'use client';

import { useId, useState, type FormEvent } from 'react';
import { Field } from '@/components/auth/AuthCard';
import { deliveryText, type Delivery } from '@/components/auth/VerificationNotice';
import { apiRequest } from '@/lib/client/http';

/** Ask for a new confirmation link (for expired or replaced links) */
export default function ResendForm({ defaultEmail = '' }: { defaultEmail?: string }) {
  const [email, setEmail] = useState(defaultEmail);
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<{ text: string; failed: boolean } | null>(null);
  const messageId = useId();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setPending(true);
    setMessage(null);
    try {
      const { delivery } = await apiRequest<{ delivery: Delivery }>('/api/auth/resend-verification', {
        method: 'POST',
        body: JSON.stringify({ email }),
      });
      setMessage({ text: deliveryText(delivery, email.trim().toLowerCase()), failed: delivery === 'failed' });
    } catch (err) {
      setMessage({ text: err instanceof Error ? err.message : 'That didn’t work', failed: true });
    } finally {
      setPending(false);
    }
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-[14px]">
      <Field
        id="resend-email"
        label="Email you signed up with"
        type="email"
        autoComplete="email"
        required
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        aria-describedby={message ? messageId : undefined}
      />
      <button type="submit" disabled={pending} className="oa-btn h-11 text-[15px]">
        {pending ? 'Sending…' : 'Send a new link'}
      </button>
      {message && (
        <p id={messageId} role={message.failed ? 'alert' : 'status'} className="m-0 text-[14px] text-ink-body">
          {message.text}
        </p>
      )}
    </form>
  );
}
