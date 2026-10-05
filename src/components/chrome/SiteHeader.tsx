'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { LogoLink } from '@/components/brand/Logo';
import { useLogout } from '@/hooks/useAuthActions';

export interface HeaderUser {
  name: string;
  email: string;
}

const PUBLIC_NAV = [
  { href: '/features', label: 'Features' },
  { href: '/#how-it-works', label: 'How it works' },
  { href: '/docs', label: 'Docs' },
];

const APP_NAV = [
  { href: '/', label: 'Check' },
  { href: '/bulk', label: 'Bulk' },
  { href: '/settings', label: 'Settings' },
  { href: '/docs', label: 'Docs' },
];

function isActive(pathname: string, href: string): boolean {
  if (href === '/') return pathname === '/' || pathname.startsWith('/results');
  if (href.includes('#')) return false;
  return pathname === href || pathname.startsWith(`${href}/`);
}

function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  return ((parts[0]?.[0] ?? '') + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase() || '?';
}

export default function SiteHeader({ user, variant = 'auto' }: { user: HeaderUser | null; variant?: 'auto' | 'minimal' }) {
  const pathname = usePathname() ?? '/';
  const nav = user ? APP_NAV : PUBLIC_NAV;

  return (
    <header className="oa-header">
      <div className="oa-wrap flex min-h-[60px] flex-wrap items-center gap-x-7 gap-y-3">
        <LogoLink href="/" />
        {variant === 'minimal' ? (
          <Link href="/" className="ml-auto px-3 py-2 text-muted no-underline hover:text-ink">
            Back to the checker
          </Link>
        ) : (
          <>
            <nav aria-label="Main" className="oa-nav ml-auto flex flex-wrap gap-1">
              {nav.map((item) => {
                const active = isActive(pathname, item.href);
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    aria-current={active ? 'page' : undefined}
                    className={`rounded px-3 py-2 no-underline ${active ? 'bg-raised text-ink' : 'text-muted'}`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </nav>
            {user ? (
              <UserMenu user={user} />
            ) : (
              <Link href="/login" className="oa-btn-outline">
                Log in
              </Link>
            )}
          </>
        )}
      </div>
    </header>
  );
}

function UserMenu({ user }: { user: HeaderUser }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const logout = useLogout();

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', close);
    };
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-haspopup="menu"
        className="flex items-center gap-[10px] border-0 bg-transparent p-0 text-[14px] text-muted cursor-pointer"
      >
        <span className="inline-flex h-7 w-7 items-center justify-center rounded-full bg-accent text-[12px] font-bold text-ground">
          {initials(user.name)}
        </span>
        <span>{user.name.split(/\s+/)[0]}</span>
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 top-[calc(100%+8px)] z-50 flex w-[220px] flex-col rounded border border-line bg-panel py-1 text-[14px]"
        >
          <span className="px-3 py-2 text-[13px] text-muted break-all">{user.email}</span>
          <Link role="menuitem" href="/settings" onClick={() => setOpen(false)} className="px-3 py-2 text-ink no-underline hover:bg-raised hover:text-ink">
            Settings and API keys
          </Link>
          <Link role="menuitem" href="/bulk" onClick={() => setOpen(false)} className="px-3 py-2 text-ink no-underline hover:bg-raised hover:text-ink">
            Bulk check
          </Link>
          <button
            role="menuitem"
            type="button"
            onClick={() => logout.submit()}
            disabled={logout.pending}
            className="border-0 border-t border-line bg-transparent px-3 py-2 text-left text-ink cursor-pointer hover:bg-raised"
          >
            {logout.pending ? 'Logging out…' : 'Log out'}
          </button>
        </div>
      )}
    </div>
  );
}
