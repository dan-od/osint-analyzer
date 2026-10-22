import Link from 'next/link';
import { Contact, LegalDoc, LegalSection, LegalTable, List, P } from '@/components/legal/LegalDoc';
import { HOSTING, OPERATOR } from '@/lib/legal';
import { RETENTION } from '@/lib/retention';
import { ANONYMOUS_CHECKS_PER_HOUR, SIGNUPS_PER_HOUR } from '@/lib/bulk-limits';
import { mailFromAddress } from '@/lib/server/mail';

// Rendered per request: the sender address comes from the server's MAIL_FROM
export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Privacy policy · OSINT Analyzer',
  description: 'What OSINT Analyzer stores, what it sends to threat-intelligence sources, the cookies it sets, and how to delete your account.',
};

const code = (s: string) => <code className="font-mono text-[13px] text-ink">{s}</code>;
const days = (n: number) => `${n} day${n === 1 ? '' : 's'}`;

export default function PrivacyPage() {
  return (
    <LegalDoc
      title="Privacy policy"
      intro={
        <P>
          OSINT Analyzer checks things you paste (a link, email, phone number, IP address or wallet) against public
          threat-intelligence sources. This page says exactly what it keeps, what it sends where, and how to delete it. There is
          no analytics, advertising or tracking of any kind.
        </P>
      }
    >
      <LegalSection id="collect" title="What is stored">
        <P>Without an account, nothing about your check is stored. With an account, the server keeps:</P>
        <List>
          <li>
            <strong className="text-ink">Your account:</strong> name, email address, and either a password hash (bcrypt; the
            password itself is never stored) or the account id that Google or GitHub gives us when you sign in with them. Also when
            the account was created, when its email was confirmed, when it was last active, how many lookups it has run, and its
            role and bulk limit.
          </li>
          <li>
            <strong className="text-ink">API keys you save in Settings,</strong> encrypted with AES-256-GCM. Only the last four
            characters are kept readable so Settings can show which key is saved, plus a daily count of how often each key was used.
          </li>
          <li>
            <strong className="text-ink">Email confirmation:</strong> when you sign up with a password or change your email, a
            single-use link is emailed to the address. The server keeps a hash of the link (never the link itself), which address
            and account it is for, when it expires ({RETENTION.verificationLinkHours} hours), when it was used and how many wrong
            passwords were tried on it; these records
            are deleted a week after they expire. Your account records when its email was confirmed. A password signup that is
            never confirmed is deleted after {days(RETENTION.unverifiedAccountDays)}.
          </li>
          <li>
            <strong className="text-ink">Recent lookup targets:</strong> the thing you checked and its type (for example
            {' '}{code('203.0.113.7')}, IP), kept {days(RETENTION.recentChecksDays)} for your dashboard.
          </li>
          <li>
            <strong className="text-ink">Bulk jobs:</strong> the job name, the list of targets, and each target&apos;s verdict so
            you can download the CSV, kept {days(RETENTION.bulkJobDays)}. Bulk results are also reused for{' '}
            {RETENTION.resultCacheHours} hours if you leave &ldquo;Reuse results&rdquo; on.
          </li>
        </List>
        <P>
          Results of single lookups are not stored, for anyone. They are worked out, shown to you and forgotten. If you click
          &ldquo;Add to CSV&rdquo;, that row is kept in your own browser, not on the server (see below).
        </P>
        <P>
          To stop abuse, the server counts requests per IP address in memory: {ANONYMOUS_CHECKS_PER_HOUR} logged-out checks and{' '}
          {SIGNUPS_PER_HOUR} new accounts an hour. These counters are never written to disk and reset within{' '}
          {RETENTION.rateLimitHours} hour or when the server restarts.
        </P>
      </LegalSection>

      <LegalSection id="third-parties" title="Who else sees what">
        <List>
          <li>
            <strong className="text-ink">Threat-intelligence sources.</strong> The target you paste is sent to the sources listed
            on its result page, and nowhere else. Which sources depends on the type of target; the full list is in the{' '}
            <Link href="/docs#sources">docs</Link>. Your name, email and account are never sent to them. If you saved your own key
            for a source, that source sees requests made with your key.
          </li>
          <li>
            <strong className="text-ink">Google and GitHub,</strong> if you choose to sign in with them. They tell us your name,
            email address, whether the email is verified, and an account id. We don&apos;t keep their access tokens and we
            don&apos;t post anything or read anything else from those accounts.
          </li>
          <li>
            <strong className="text-ink">Resend</strong> sends the confirmation emails (from {mailFromAddress()}), so it
            receives your email address, your name and the message with its link, under its own privacy policy. Nothing else is
            sent by email: no newsletters or marketing.
          </li>
          <li>
            <strong className="text-ink">Cloudflare</strong> carries traffic to the site, so it handles your IP address and requests
            in transit, under its own privacy policy.
          </li>
        </List>
        <P>Nothing is sold, shared for marketing, or given to anyone else unless the law requires it.</P>
      </LegalSection>

      <LegalSection id="cookies" title="Cookies and browser storage">
        <P>
          The site sets only the cookies it needs for signing in. All are strictly necessary, {code('HttpOnly')} (page scripts
          can&apos;t read them) and {code('SameSite=Lax')}. On the live site they carry the{' '}
          {code('__Secure-')} or {code('__Host-')} prefix shown in brackets, which means they are only ever sent over HTTPS.
          Visiting without logging in sets no cookies at all.
        </P>
        <LegalTable
          caption="Cookies"
          head={['Name', 'Purpose', 'How long']}
          rows={[
            [
              <>authjs.session-token<br />(__Secure-)</>,
              'Keeps you logged in. Holds a random token; the matching record on the server is deleted when you log out.',
              `${days(RETENTION.sessionDays)}, or until you log out`,
            ],
            [<>authjs.csrf-token<br />(__Host-)</>, 'Protects the log-in forms against cross-site request forgery.', 'Until you close the browser'],
            [<>authjs.callback-url<br />(__Secure-)</>, 'Remembers which page to return to after logging in.', 'Until you close the browser'],
            [
              <>authjs.state, authjs.pkce.code_verifier, authjs.nonce<br />(__Secure-)</>,
              'Only while you sign in with Google or GitHub (one or more of these, depending on the provider): checks that the answer coming back belongs to the sign-in you started.',
              '15 minutes at most; removed once sign-in finishes',
            ],
          ]}
        />
        <LegalTable
          caption="Browser storage (never sent to the server)"
          head={['Name', 'Purpose', 'How long']}
          rows={[
            [code('oa-csv-rows'), 'localStorage: rows you collected with "Add to CSV" (target, verdict, scores).', 'Until you clear the list or your browser data'],
            [code('oa-bulk-handoff'), 'sessionStorage: a list pasted on the dashboard, carried to the bulk page.', 'Read once, then removed'],
          ]}
        />
        <P>
          Because there is no analytics, advertising or tracking, there is nothing to consent to and no cookie banner. If
          analytics is ever added, it will be off unless you switch it on, and this page will say so first.
        </P>
      </LegalSection>

      <LegalSection id="retention" title="How long things are kept">
        <LegalTable
          caption="Retention"
          head={['What', 'Kept for']}
          rows={[
            ['Account, saved API keys, linked Google/GitHub ids', 'Until you delete the account (or a key, or unlink a provider)'],
            ['Email confirmation links (hashed)', `Valid ${RETENTION.verificationLinkHours} hours; the record is deleted a week after that`],
            ['Password signups never confirmed', days(RETENTION.unverifiedAccountDays)],
            ['Recent lookup targets', days(RETENTION.recentChecksDays)],
            ['Bulk jobs with their targets and results', days(RETENTION.bulkJobDays)],
            ['Reusable bulk results', `${RETENTION.resultCacheHours} hours`],
            ['Daily API key usage counts', days(RETENTION.usageCounterDays)],
            ['Sign-in sessions', `${days(RETENTION.sessionDays)}, or until you log out`],
            ['Rate-limit counters (memory only)', `Up to ${RETENTION.rateLimitHours} hour`],
            ['Single lookup results', 'Not stored'],
          ]}
        />
        <P>Expired data is deleted automatically every hour.</P>
      </LegalSection>

      <LegalSection id="delete" title="Deleting your data">
        <List>
          <li>
            <Link href="/settings#delete">Settings → Delete my account</Link> removes your account straight away, together with
            every session, linked Google/GitHub account, saved API key, recent check and bulk job. There is no grace period and
            no copy is kept.
          </li>
          <li>Each saved API key can be removed on its own in Settings.</li>
          <li>Google or GitHub can be unlinked in Settings, as long as you keep at least one way to sign in.</li>
          <li>
            If you can&apos;t sign in any more, email <Contact /> from the account&apos;s
            address and it will be deleted for you.
          </li>
        </List>
      </LegalSection>

      <LegalSection id="security" title="How it is protected">
        <P>
          Passwords are hashed with bcrypt. Saved API keys are encrypted, and each one is tied to its account, so a copied key
          can&apos;t be read under another account. Session tokens are stored only as a hash. The site is served over HTTPS.
        </P>
      </LegalSection>

      <LegalSection id="who" title="Who runs it">
        <P>
          OSINT Analyzer is run by {OPERATOR} as an individual, not a company. It is hosted on {HOSTING}. Questions, requests and
          complaints: <Contact />. Both addresses reach the same person.
        </P>
        <P>If this policy changes, the date at the top changes with it.</P>
      </LegalSection>
    </LegalDoc>
  );
}
