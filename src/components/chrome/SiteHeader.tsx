'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { LogoLink } from '@/components/brand/Logo';
import { useLogout } from '@/hooks/useAuthActions';

export interface HeaderUser {
  name: string;
  email: string;
  admin?: boolean;
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

const ADMIN_NAV = { href: '/admin', label: 'Admin' };

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
  const nav = user ? (user.admin ? [...APP_NAV, ADMIN_NAV] : APP_NAV) : PUBLIC_NAV;
  const [menuOpen, setMenuOpen] = useState(false);
  const menuButton = useRef<HTMLButtonElement>(null);
  const wasOpen = useRef(false);

  // Close the phone menu on navigation, on Escape, and when the screen widens past the breakpoint
  useEffect(() => setMenuOpen(false), [pathname]);
  useEffect(() => {
    if (!menuOpen) {
      // Closing hands focus back to the button that opened the menu
      if (wasOpen.current && window.innerWidth <= 720) {
        menuButton.current?.focus();
      }
      wasOpen.current = false;
      return;
    }
    wasOpen.current = true;
    const panel = document.getElementById('mobile-menu');
    const focusables = () => [
      menuButton.current,
      ...Array.from(panel?.querySelectorAll<HTMLElement>('a[href], button:not([disabled])') ?? []),
    ].filter((el): el is HTMLElement => !!el);
    focusables()[1]?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setMenuOpen(false);
        return;
      }
      // Focus stays inside the open menu (its button plus its items)
      if (e.key === 'Tab') {
        const items = focusables();
        const i = items.indexOf(document.activeElement as HTMLElement);
        const next = e.shiftKey ? (i <= 0 ? items.length - 1 : i - 1) : i === items.length - 1 || i < 0 ? 0 : i + 1;
        e.preventDefault();
        items[next]?.focus();
      }
    };
    const onResize = () => window.innerWidth > 720 && setMenuOpen(false);
    document.addEventListener('keydown', onKey);
    window.addEventListener('resize', onResize);
    return () => {
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('resize', onResize);
    };
  }, [menuOpen]);

  return (
    <header className="oa-header">
      <div className="oa-wrap flex min-h-[60px] items-center gap-x-7 max-[720px]:min-h-[56px]">
        <LogoLink href="/" />
        {variant === 'minimal' ? (
          <Link href="/" className="ml-auto px-3 py-2 text-muted no-underline hover:text-ink">
            Back to the checker
          </Link>
        ) : (
          <>
            <button
              ref={menuButton}
              type="button"
              onClick={() => setMenuOpen((v) => !v)}
              aria-expanded={menuOpen}
              aria-controls="mobile-menu"
              aria-label={menuOpen ? 'Close menu' : 'Open menu'}
              className="-mr-2 ml-auto inline-flex h-11 w-11 items-center justify-center rounded border-0 bg-transparent text-muted hover:text-ink min-[721px]:hidden"
            >
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true" focusable="false">
                {menuOpen ? <path d="M6 6l12 12M18 6 6 18" /> : <path d="M4 7h16M4 12h16M4 17h16" />}
              </svg>
            </button>
            <nav aria-label="Main" className="oa-nav ml-auto flex flex-wrap gap-1 max-[720px]:hidden">
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
            <div className="max-[720px]:hidden">
              {user ? (
                <UserMenu user={user} />
              ) : (
                <Link href="/login" className="oa-btn-outline">
                  Log in
                </Link>
              )}
            </div>
          </>
        )}
      </div>
      {variant !== 'minimal' && (
        <MobileMenu open={menuOpen} nav={nav} pathname={pathname} user={user} onNavigate={() => setMenuOpen(false)} />
      )}
    </header>
  );
}

/** Phone menu (under 720px): a solid panel below the header row */
function MobileMenu({
  open,
  nav,
  pathname,
  user,
  onNavigate,
}: {
  open: boolean;
  nav: { href: string; label: string }[];
  pathname: string;
  user: HeaderUser | null;
  onNavigate: () => void;
}) {
  const logout = useLogout();
  const item = (active: boolean) =>
    `block border-l-2 px-4 py-3 text-[16px] no-underline ${
      active ? 'border-l-accent bg-raised text-ink hover:text-ink' : 'border-l-transparent text-ink-body hover:border-l-accent hover:bg-raised hover:text-ink'
    }`;
  return (
    <div
      id="mobile-menu"
      hidden={!open}
      className="border-t border-line bg-ground min-[721px]:!hidden"
      style={{ paddingBottom: 'max(12px, env(safe-area-inset-bottom))' }}
    >
      <nav aria-label="Main (menu)" className="oa-wrap flex flex-col gap-1 pt-3">
        {nav.map((link) => {
          const active = isActive(pathname, link.href);
          return (
            <Link key={link.href} href={link.href} onClick={onNavigate} aria-current={active ? 'page' : undefined} className={item(active)}>
              {link.label}
            </Link>
          );
        })}
        <div className="my-2 border-t border-line" />
        {user ? (
          <>
            <span className="break-all px-4 py-1 text-[13px] text-muted">Signed in as {user.email}</span>
            <button
              type="button"
              onClick={() => logout.submit()}
              disabled={logout.pending}
              className={`${item(false)} w-full border-y-0 border-r-0 bg-transparent text-left`}
            >
              {logout.pending ? 'Logging out…' : 'Log out'}
            </button>
          </>
        ) : (
          <Link href="/login" onClick={onNavigate} className={item(pathname === '/login')}>
            Log in
          </Link>
        )}
      </nav>
    </div>
  );
}

/** Account disclosure: a button that shows a short list of links. Tab moves
 *  through them; Escape or tabbing out closes it. */
function UserMenu({ user }: { user: HeaderUser }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const logout = useLogout();

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      setOpen(false);
      button.current?.focus();
    };
    const onFocus = (e: FocusEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    document.addEventListener('focusin', onFocus);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('focusin', onFocus);
    };
  }, [open]);

  const item = 'block px-3 py-2 text-ink no-underline hover:bg-raised hover:text-ink';

  return (
    <div ref={ref} className="relative">
      <button
        ref={button}
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-controls="user-menu"
        className="flex items-center gap-[10px] border-0 bg-transparent p-0 text-[14px] text-muted cursor-pointer"
      >
        <span aria-hidden="true" className="inline-flex h-7 w-7 items-center justify-center rounded-full bg-accent text-[12px] font-bold text-ground">
          {initials(user.name)}
        </span>
        <span>{user.name.split(/\s+/)[0]}</span>
        <span className="oa-sr">, account menu</span>
      </button>
      <div
        id="user-menu"
        hidden={!open}
        className="absolute right-0 top-[calc(100%+8px)] z-50 w-[220px] rounded border border-line bg-panel py-1 text-[14px]"
      >
        <p className="m-0 break-all px-3 py-2 text-[13px] text-muted">{user.email}</p>
        <ul className="m-0 list-none p-0">
          <li>
            <Link href="/settings" onClick={() => setOpen(false)} className={item}>
              Settings and API keys
            </Link>
          </li>
          <li>
            <Link href="/bulk" onClick={() => setOpen(false)} className={item}>
              Bulk check
            </Link>
          </li>
          <li className="border-t border-line">
            <button
              type="button"
              onClick={() => logout.submit()}
              disabled={logout.pending}
              className="w-full border-0 bg-transparent px-3 py-2 text-left text-ink cursor-pointer hover:bg-raised"
            >
              {logout.pending ? 'Logging out…' : 'Log out'}
            </button>
          </li>
        </ul>
      </div>
    </div>
  );
}
