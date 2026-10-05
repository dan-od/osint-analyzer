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
      <SiteHeader user={user ? { name: user.name, email: user.email } : null} variant={header} />
      {children}
      <SiteFooter />
    </div>
  );
}
