import Link from 'next/link';
import { SweepMark } from '@/components/brand/Logo';
import { SOURCE_COUNT } from '@/lib/source-catalog';

const linkCls = 'text-muted no-underline hover:text-ink';
const iconCls =
  'inline-flex h-9 w-9 items-center justify-center rounded border border-line text-ink-body hover:border-line-hover hover:text-ink';

export default function SiteFooter() {
  return (
    <footer className="oa-footer mt-auto border-t border-line bg-foot text-[14px] text-muted">
      <div className="oa-wrap flex flex-col gap-10 pb-6 pt-14">
        <div className="flex flex-wrap gap-x-12 gap-y-8">
          <div className="flex min-w-0 max-w-[380px] max-[720px]:max-w-none flex-[2_1_280px] flex-col gap-[14px]">
            <Link href="/" className="flex items-center gap-[10px] text-[15px] font-semibold text-ink no-underline hover:text-ink">
              <SweepMark size={22} />
              <span>OSINT Analyzer</span>
            </Link>
            <p className="m-0 text-muted">
              Paste a link, email, number, IP or wallet and get a plain-words verdict backed by {SOURCE_COUNT} public
              threat-intelligence sources. Public checks are not stored.
            </p>
            <div className="flex gap-[10px]">
              <a href="https://www.linkedin.com/in/daniel-okoro-3905a328b" target="_blank" rel="noopener noreferrer" aria-label="LinkedIn" className={iconCls}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                  <path d="M4.98 3.5a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5ZM3 9h4v12H3zM10 9h3.8v1.7h.1c.5-1 1.8-2 3.7-2 4 0 4.7 2.6 4.7 6V21h-4v-5.3c0-1.3 0-2.9-1.8-2.9s-2 1.4-2 2.8V21h-4z" />
                </svg>
              </a>
              <a href="mailto:daniel.ookoro@gmail.com" aria-label="Email" className={iconCls}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <rect x="3" y="5" width="18" height="14" rx="1" />
                  <path d="m3 7 9 6 9-6" />
                </svg>
              </a>
              <a href="https://okoro.me" target="_blank" rel="noopener noreferrer" aria-label="Portfolio" className={iconCls}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <circle cx="12" cy="12" r="9" />
                  <path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" />
                </svg>
              </a>
            </div>
          </div>
          <div className="flex min-w-0 flex-[1_1_140px] flex-col gap-[10px]">
            <span className="font-semibold text-ink">Product</span>
            <Link href="/" className={linkCls}>Check something</Link>
            <Link href="/features" className={linkCls}>Features</Link>
            <Link href="/#how-it-works" className={linkCls}>How it works</Link>
            <Link href="/docs" className={linkCls}>Docs</Link>
          </div>
          <div className="flex min-w-0 flex-[1_1_140px] flex-col gap-[10px]">
            <span className="font-semibold text-ink">For teams</span>
            <Link href="/login" className={linkCls}>Log in</Link>
            <Link href="/signup" className={linkCls}>Create an account</Link>
            <Link href="/bulk" className={linkCls}>Bulk checks</Link>
            <Link href="/settings" className={linkCls}>API keys</Link>
          </div>
          <div className="flex min-w-0 flex-[1_1_140px] flex-col gap-[10px]">
            <span className="font-semibold text-ink">Sources</span>
            <a href="https://www.spamhaus.org/" target="_blank" rel="noopener noreferrer" className={linkCls}>Spamhaus</a>
            <a href="https://abuse.ch/" target="_blank" rel="noopener noreferrer" className={linkCls}>abuse.ch</a>
            <a href="https://www.abuseipdb.com/" target="_blank" rel="noopener noreferrer" className={linkCls}>AbuseIPDB</a>
            <a href="https://www.virustotal.com/" target="_blank" rel="noopener noreferrer" className={linkCls}>VirusTotal</a>
            <Link href="/docs#sources" className={linkCls}>All {SOURCE_COUNT}</Link>
          </div>
        </div>
        <div className="flex flex-wrap justify-between gap-x-6 gap-y-2 border-t border-line pt-5 text-[13px] text-faint">
          <span>© {new Date().getFullYear()} OSINT Analyzer. Not affiliated with any of the sources it queries.</span>
          <nav aria-label="Legal" className="flex gap-4">
            <Link href="/privacy" className="text-muted">Privacy</Link>
            <Link href="/terms" className="text-muted">Terms</Link>
          </nav>
          <span>
            Built by{' '}
            <a href="https://www.linkedin.com/in/daniel-okoro-3905a328b" target="_blank" rel="noopener noreferrer" className="text-muted">
              Daniel Okoro
            </a>
          </span>
        </div>
      </div>
    </footer>
  );
}
