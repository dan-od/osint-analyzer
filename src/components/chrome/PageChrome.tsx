// Header + footer around every page. Server component: the header variant
// (public or logged in) comes from the session, so there is no flash.
import type { ReactNode } from 'react';
import { getCurrentUser } from '@/lib/server/auth/session';
import SiteHeader from './SiteHeader';
import SiteFooter from './SiteFooter';

export default function PageChrome({ children, header = 'auto' }: { children: ReactNode; header?: 'auto' | 'minimal' }) {
  const user = getCurrentUser();
  return (
    <div className="oa-page">
      {/* First thing a keyboard user reaches; visible only when focused */}
      <a href="#main" className="oa-skip">
        Skip to content
      </a>
      <SiteHeader user={user ? { name: user.name, email: user.email, admin: user.role === 'admin' } : null} variant={header} />
      <main id="main" tabIndex={-1} className="flex flex-auto flex-col outline-none">
        {children}
      </main>
      <SiteFooter />
    </div>
  );
}
