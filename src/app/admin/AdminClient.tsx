'use client';

import { useState, type FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import { FormMessage } from '@/components/auth/AuthCard';
import { apiRequest } from '@/lib/client/http';
import type { AdminUserRow } from '@/types/account';

export interface AdminRowView extends AdminUserRow {
  createdLabel: string;
  activeLabel: string;
}

interface Props {
  rows: AdminRowView[];
  meId: number;
  defaultCap: number;
  maxCap: number;
}

/** Column label shown above each value on phones, where the table becomes cards */
const PhoneLabel = ({ children }: { children: string }) => (
  <span className="hidden text-[12px] text-faint max-[720px]:block">{children}</span>
);

const td = 'max-[720px]:!px-0 max-[720px]:!py-0 max-[720px]:!border-0';

export default function AdminClient({ rows, meId, defaultCap, maxCap }: Props) {
  const router = useRouter();
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const act = async (id: number, init: RequestInit) => {
    setBusy(id);
    setError(null);
    try {
      await apiRequest(`/api/admin/users/${id}`, init);
      router.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'That didn’t work');
    } finally {
      setBusy(null);
    }
  };

  const patch = (id: number, body: object) => act(id, { method: 'PATCH', body: JSON.stringify(body) });

  return (
    <div className="oa-wrap flex flex-col gap-4 pb-12 pt-7">
      {error && <FormMessage>{error}</FormMessage>}
      <div className="oa-tablewrap max-[720px]:border-0">
        <table aria-label="Accounts" className="oa-table">
          <thead className="max-[720px]:hidden">
            <tr>
              <th scope="col">Account</th>
              <th scope="col">Created</th>
              <th scope="col">Last active</th>
              <th scope="col" className="text-right">Lookups</th>
              <th scope="col">Bulk cap per job</th>
              <th scope="col">Status</th>
              <th scope="col">
                <span className="oa-sr">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((u) => {
              const isAdmin = u.role === 'admin';
              const pending = busy === u.id;
              return (
                <tr
                  key={u.id}
                  className={`max-[720px]:mb-3 max-[720px]:grid max-[720px]:grid-cols-2 max-[720px]:gap-x-4 max-[720px]:gap-y-3 max-[720px]:rounded max-[720px]:border max-[720px]:border-line max-[720px]:p-4 ${u.disabled ? 'text-muted' : ''}`}
                >
                  <td className={`${td} max-[720px]:col-span-2`}>
                    <div className="flex flex-col gap-[2px]">
                      <span className="break-all font-semibold text-ink">
                        {u.email}
                        {u.id === meId && <span className="font-normal text-muted"> (you)</span>}
                      </span>
                      <span className="text-[13px] text-muted">
                        {u.name}
                        {isAdmin && <span className="oa-chip ml-2 align-[1px]">Admin</span>}
                      </span>
                    </div>
                  </td>
                  <td className={`${td} whitespace-nowrap`}>
                    <PhoneLabel>Created</PhoneLabel>
                    {u.createdLabel}
                  </td>
                  <td className={`${td} whitespace-nowrap`}>
                    <PhoneLabel>Last active</PhoneLabel>
                    {u.activeLabel}
                  </td>
                  <td className={`${td} text-right font-mono max-[720px]:text-left`}>
                    <PhoneLabel>Lookups</PhoneLabel>
                    {u.lookups}
                  </td>
                  <td className={td}>
                    <PhoneLabel>Bulk cap per job</PhoneLabel>
                    {isAdmin ? (
                      <span className="font-mono">{maxCap}</span>
                    ) : (
                      <CapForm user={u} defaultCap={defaultCap} maxCap={maxCap} pending={pending} onSave={(cap) => patch(u.id, { bulkCap: cap })} />
                    )}
                  </td>
                  <td className={`${td} whitespace-nowrap`}>
                    <PhoneLabel>Status</PhoneLabel>
                    {u.disabled ? (
                      <span>
                        <span className="oa-dot skip" />
                        Disabled
                      </span>
                    ) : u.emailVerified ? (
                      'Active'
                    ) : (
                      <span>
                        <span className="oa-dot skip" />
                        Email not confirmed
                      </span>
                    )}
                  </td>
                  <td className={`${td} max-[720px]:col-span-2`}>
                    {!isAdmin && (
                      <div className="flex flex-wrap justify-end gap-2 max-[720px]:justify-start">
                        <button
                          type="button"
                          disabled={pending}
                          className="oa-btn h-9 px-3 text-[13px]"
                          onClick={() => {
                            if (u.disabled || window.confirm(`Disable ${u.email}? They are signed out and their bulk jobs stop.`)) {
                              void patch(u.id, { disabled: !u.disabled });
                            }
                          }}
                        >
                          {u.disabled ? 'Enable' : 'Disable'}
                        </button>
                        <button
                          type="button"
                          disabled={pending}
                          className="oa-btn h-9 px-3 text-[13px]"
                          onClick={() => {
                            if (window.confirm(`Delete ${u.email}? Their keys, jobs and history are removed. This can’t be undone.`)) {
                              void act(u.id, { method: 'DELETE' });
                            }
                          }}
                        >
                          Delete
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function CapForm({
  user,
  defaultCap,
  maxCap,
  pending,
  onSave,
}: {
  user: AdminRowView;
  defaultCap: number;
  maxCap: number;
  pending: boolean;
  onSave: (cap: number | null) => void;
}) {
  const [value, setValue] = useState(String(user.bulkCap));
  const cap = Number(value);
  const valid = Number.isInteger(cap) && cap >= 1 && cap <= maxCap;
  const changed = valid && cap !== user.bulkCap;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (changed) onSave(cap === defaultCap ? null : cap);
  };

  return (
    <form onSubmit={submit} className="flex items-center gap-2">
      <label htmlFor={`cap-${user.id}`} className="oa-sr">
        Bulk cap for {user.email}
      </label>
      <input
        id={`cap-${user.id}`}
        type="number"
        inputMode="numeric"
        min={1}
        max={maxCap}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        className="oa-input oa-mono h-9 w-[84px] px-2 text-[14px]"
      />
      <button type="submit" disabled={pending || !changed} className="oa-btn h-9 px-3 text-[13px]">
        Save
      </button>
      {user.customBulkCap === null && <span className="text-[12px] text-faint">default</span>}
    </form>
  );
}
