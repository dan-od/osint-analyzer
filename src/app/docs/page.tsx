import type { ReactNode } from 'react';
import Link from 'next/link';
import PageChrome from '@/components/chrome/PageChrome';
import DocsNav, { type DocsNavItem } from '@/components/docs/DocsNav';
import { CornerTicks, MarkBleed } from '@/components/decor';
import { API_BLOCKLIST_TRUST, DOMAIN_DNSBL_META, FEED_META, IP_DNSBL_META } from '@/lib/blocklist-meta';
import { IP_DNSBL_COUNT, KEYLESS_SOURCE_COUNT, SOURCE_COUNT, SOURCES, sourceCountFor } from '@/lib/source-catalog';
import { SERVICES } from '@/lib/services';
import { COVERAGE_THRESHOLDS, FAIL_MULTIPLIER, RISK_BANDS, SEVERITY_POINTS, TRUST_WEIGHT } from '@/lib/scoring-rules';
import {
  ANONYMOUS_CHECKS_PER_HOUR,
  BULK_MAX_TARGETS,
  DNSBL_TIMEOUT_SECONDS,
  minutesFreeOnly,
  SOURCE_TIMEOUT_SECONDS,
  TYPICAL_CHECK_SECONDS,
  VT_PER_MINUTE,
} from '@/lib/bulk-limits';
import { levelWord } from '@/lib/verdict';
import type { AnalysisType, BlocklistTrust, RiskLevel } from '@/types';

export const metadata = { title: 'Docs · OSINT Analyzer' };

const NAV: DocsNavItem[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'quick-start', label: 'Quick start' },
  { id: 'input-types', label: 'Input types' },
  { id: 't-ip', label: 'IP address', sub: true },
  { id: 't-domain', label: 'Domain or URL', sub: true },
  { id: 't-email', label: 'Email', sub: true },
  { id: 't-phone', label: 'Phone', sub: true },
  { id: 't-crypto', label: 'Crypto wallet', sub: true },
  { id: 'reading', label: 'Reading a result' },
  { id: 'scoring', label: 'How the score works' },
  { id: 'bulk', label: 'Bulk checks' },
  { id: 'keys', label: 'API keys' },
  { id: 'privacy', label: 'Privacy and limits' },
];

const INPUT_TYPES: { id: string; type: AnalysisType; title: string; example: string; text: string; looks: string[]; sources: string }[] = [
  {
    id: 't-ip',
    type: 'ip',
    title: 'IP address',
    example: '203.0.113.42',
    text: 'IPv4 and IPv6. Private, loopback and CGNAT ranges are recognised and not sent anywhere. Checking IPs needs an account.',
    looks: ['Abuse confidence score', `DNS blocklists (${IP_DNSBL_COUNT})`, 'VPN / proxy / Tor', 'Open ports and CVEs', 'Scanner vs targeted', 'Daily threat feeds', 'Country and AS owner'],
    sources: `AbuseIPDB, VirusTotal, GreyNoise, Shodan InternetDB, ${IP_DNSBL_COUNT} DNSBLs (Spamhaus ZEN, SpamCop, Barracuda, UCEPROTECT and more), ${FEED_META.map((f) => f.name.replace(/ \(.*\)/, '')).join(', ')}, URLhaus, ThreatFox, AlienVault OTX, IP2Proxy (if installed)`,
  },
  {
    id: 't-domain',
    type: 'domain',
    title: 'Domain or URL',
    example: 'example-login.example',
    text: 'A bare domain or a full link. Links are checked by their host name.',
    looks: ['Registration date and age', 'DNS records', 'Phishing feeds', 'Malware feeds', 'Safe Browsing', 'Domain blocklists', 'Look-alike of a known brand', 'Suspicious TLD', 'Behind a CDN?'],
    sources: `VirusTotal, Google Safe Browsing, URLhaus, ThreatFox, PhishTank, OpenPhish, PhishStats, ${DOMAIN_DNSBL_META.map((m) => m.name).join(', ')}, AlienVault OTX, WHOIS, plus AbuseIPDB and the ${IP_DNSBL_COUNT} IP blocklists on the address it resolves to`,
  },
  {
    id: 't-email',
    type: 'email',
    title: 'Email address',
    example: 'ceo@pay-now.example',
    text: 'The address, and the domain it belongs to.',
    looks: ['Valid format', 'Mailbox exists', 'Fraud score', 'Disposable or honeypot', 'Known breaches', 'MX / SPF / DMARC', 'Domain age'],
    sources: 'IPQualityScore, Hunter.io, Have I Been Pwned, EmailRep, DNS, WHOIS, Spamhaus DBL',
  },
  {
    id: 't-phone',
    type: 'phone',
    title: 'Phone number',
    example: '+1 416 555 0100',
    text: 'Any country. Include the country code (+1 for Canada and the US); numbers are checked as written.',
    looks: ['Valid format', 'Carrier and region', 'Line type (mobile, landline, VoIP)', 'Spam and fraud reports', 'Premium-rate patterns'],
    sources: 'IPQualityScore, NumVerify, pattern rules',
  },
  {
    id: 't-crypto',
    type: 'crypto',
    title: 'Crypto wallet',
    example: 'bc1q9x…k2d',
    text: 'Bitcoin and Ethereum addresses.',
    looks: ['Scam reports', 'Ransomware payment addresses', 'Sanctions lists (OFAC)', 'Community scam databases'],
    sources: 'ChainAbuse, BTC Black, OpenSanctions, Chainalysis (OFAC), GitHub scam lists, Blockchain.info or Etherscan',
  },
];

/** Every blocklist and threat feed, grouped by the trust weight the scorer gives it */
function trustTiers(): Record<BlocklistTrust, string[]> {
  const tiers: Record<BlocklistTrust, string[]> = { high: [], medium: [], low: [], noisy: [] };
  const add = (name: string, trust: BlocklistTrust) => {
    if (!tiers[trust].includes(name)) tiers[trust].push(name);
  };
  IP_DNSBL_META.forEach((m) => add(m.name, m.trust));
  DOMAIN_DNSBL_META.forEach((m) => add(m.name, m.trust));
  FEED_META.forEach((m) => add(m.name.replace(/ \(.*\)/, ''), m.trust));
  Object.values(API_BLOCKLIST_TRUST).forEach((m) => add(m.name, m.trust));
  return tiers;
}

const TIER_WHY: Record<BlocklistTrust, string> = {
  high: 'Curated, low false-positive rate',
  medium: 'Good, but crowd-sourced or broad',
  low: 'Smaller lists, or a hint rather than proof (Tor exits)',
  noisy: 'List whole ranges or networks',
};

const h2 = 'oa-display text-[26px]';
const body = 'm-0 text-ink-body';
const mono = 'font-mono text-[13px]';
const chip = 'rounded bg-raised px-2 py-1 text-[12px] text-ink-body';

function Section({ id, children }: { id: string; children: ReactNode }) {
  return (
    <section id={id} className="flex scroll-mt-5 flex-col gap-[14px]">
      {children}
    </section>
  );
}

function Status({ tone, word }: { tone: 'fail' | 'warn' | 'pass' | 'skip'; word: string }) {
  const ink = { fail: 'text-fail-ink font-semibold', warn: 'text-warn font-semibold', pass: 'text-pass-ink font-medium', skip: 'text-skip' }[tone];
  return (
    <span className={ink}>
      <span className={`oa-dot ${tone}`} />
      {word}
    </span>
  );
}

const LEVEL_INK: Record<RiskLevel, string> = { low: 'text-pass-ink', medium: 'text-warn', high: 'text-fail-ink', critical: 'text-fail-ink' };

export default function DocsPage() {
  const tiers = trustTiers();
  const keyless = SOURCES.filter((s) => !s.service && !s.serverKeyEnv);
  const serverOnly = SOURCES.filter((s) => s.serverKeyEnv);

  return (
    <PageChrome>
      <section aria-label="Docs title" className="oa-dots relative overflow-hidden border-b border-line">
        <MarkBleed size={340} style={{ right: -60, top: -90 }} />
        <div className="oa-wrap relative flex flex-col gap-2 pb-9 pt-11">
          <h1 className="oa-h1 oa-display text-[40px] leading-[1.05]">Docs</h1>
          <p className="m-0 max-w-[64ch] text-muted">
            Everything the tool does, what each result means, and how the score is put together. Short on purpose.
          </p>
        </div>
      </section>

      <div className="oa-wrap flex flex-wrap items-start gap-10 pb-16 pt-8">
        <DocsNav items={NAV} />

        <main className="flex min-w-0 max-w-[820px] flex-[999_1_560px] flex-col gap-14">
          <Section id="overview">
            <h2 className={h2}>Overview</h2>
            <p className={body}>
              OSINT Analyzer takes one thing you are unsure about, works out what kind of thing it is, and asks a set of public
              and free threat-intelligence sources about it at the same time. It then turns the answers into a single verdict
              with a score, lists every finding with its source, and suggests what to do next.
            </p>
            <p className={body}>
              It is a triage tool, not a court. A high score means several independent sources agree something is wrong. A low
              score means nobody has reported it yet, which is not the same as safe.
            </p>
            <div className="oa-g1 mt-1 grid grid-cols-3 gap-3">
              {[
                ['5', 'kinds of target'],
                [String(SOURCE_COUNT), `sources, ${KEYLESS_SOURCE_COUNT} of them free with no key`],
                ['0', 'public check results stored on the server'],
              ].map(([n, label]) => (
                <div key={label} className="flex flex-col gap-1 rounded border border-line px-4 py-[14px]">
                  <span className="font-mono text-[24px] text-ink-strong">{n}</span>
                  <span className="text-[13px] text-muted">{label}</span>
                </div>
              ))}
            </div>
          </Section>

          <Section id="quick-start">
            <h2 className={h2}>Quick start</h2>
            <ol className="m-0 flex list-none flex-col gap-[10px] p-0">
              {[
                <>Paste the suspicious thing into the box on the <Link href="/">home page</Link>. A link, an email address, a phone number, an IP, or a wallet address.</>,
                <>Check the detected type next to the box. If it guessed wrong, edit what you pasted (for example, drop a stray space) and it updates as you type.</>,
                <>
                  Press Check. Results start arriving within a second; the full set usually takes {TYPICAL_CHECK_SECONDS.min} to{' '}
                  {TYPICAL_CHECK_SECONDS.max} seconds. A source that takes longer than {SOURCE_TIMEOUT_SECONDS} seconds is marked as timed out.
                </>,
                <>Read the verdict at the top, then the flagged rows in the findings table. Use Copy link to share the result with someone else.</>,
              ].map((text, i) => (
                <li key={i} className="flex items-start gap-[14px]">
                  <span className="inline-flex h-[26px] w-[26px] flex-none items-center justify-center rounded bg-raised font-mono text-[12px] text-accent">{i + 1}</span>
                  <span className="text-ink-body">{text}</span>
                </li>
              ))}
            </ol>
            <div className="rounded border border-line border-l-[3px] border-l-accent bg-panel px-4 py-3 text-[14px] text-ink-body">
              On a SOC rotation? <Link href="/login">Log in</Link> to unlock IP checks, bulk checks and your own API keys. See{' '}
              <a href="#bulk">Bulk checks</a> and <a href="#keys">API keys</a> below.
            </div>
          </Section>

          <Section id="input-types">
            <h2 className={h2}>Input types</h2>
            <p className={body}>The type is detected from what you paste. Each type runs its own set of checks against its own set of sources.</p>
            <div className="flex flex-col gap-[14px]">
              {INPUT_TYPES.map((t) => (
                <div key={t.id} id={t.id} className="oa-g1 relative grid scroll-mt-5 grid-cols-2 overflow-hidden rounded border border-line">
                  <CornerTicks />
                  <div className="flex min-w-0 flex-col gap-[10px] bg-panel px-[22px] py-5">
                    <h3 className="m-0 text-[17px] font-semibold">{t.title}</h3>
                    <span className="inline-flex h-9 items-center overflow-hidden whitespace-nowrap rounded border border-line-strong bg-ground px-3 font-mono text-[13px] text-accent">
                      {t.example}
                    </span>
                    <p className="m-0 text-[14px] text-muted">{t.text}</p>
                  </div>
                  <div className="flex min-w-0 flex-col gap-[10px] border-l border-line px-[22px] py-5">
                    <span className="text-[12px] text-muted">What we look at</span>
                    <div className="flex flex-wrap gap-[5px]">
                      {t.looks.map((l) => (
                        <span key={l} className={chip}>{l}</span>
                      ))}
                    </div>
                    <span className="mt-1 text-[12px] text-muted">Sources ({sourceCountFor(t.type)})</span>
                    <span className="text-[13px] text-ink-body">{t.sources}</span>
                  </div>
                </div>
              ))}
            </div>
          </Section>

          <Section id="reading">
            <h2 className={h2}>Reading a result</h2>
            <div className="oa-tablewrap">
              <table className="oa-table oa-stack min-w-[520px]">
                <thead>
                  <tr>
                    <th scope="col" className="w-[120px]">Status</th>
                    <th scope="col">Meaning</th>
                  </tr>
                </thead>
                <tbody>
                  <tr><td><Status tone="fail" word="Fail" /></td><td className="text-ink-body">A source reported something bad: listed on a blocklist, abuse reports, a failed verification. Adds to the score.</td></tr>
                  <tr><td><Status tone="warn" word="Warn" /></td><td className="text-ink-body">Not bad on its own, but worth knowing: a very new domain, a missing DMARC record, a VoIP line. Adds a little.</td></tr>
                  <tr><td><Status tone="pass" word="Pass" /></td><td className="text-ink-body">The source was asked and had nothing against the target.</td></tr>
                  <tr><td><Status tone="skip" word="Skipped" /></td><td className="text-ink-body">The source gave no usable answer: no API key, quota used up, refused, or timed out. Skipped never counts for or against.</td></tr>
                </tbody>
              </table>
            </div>
            <p className={body}>
              Flagged rows always sort to the top. Each row names its source so you can go and look yourself; the Open in panel
              links straight to the target on VirusTotal, AbuseIPDB, URLVoid (domains) and IPVoid (IPs; IPVoid only offers a form,
              so the link opens it for you to paste into).
            </p>
            <div className="rounded border border-line border-l-[3px] border-l-accent bg-panel px-4 py-3 text-[14px] text-ink-body">
              <strong className="text-ink">Sites behind a CDN.</strong> If a domain resolves to a Cloudflare or Fastly address (or
              AbuseIPDB marks the address as a CDN), IP-level results describe the CDN, not the site. The result says so on the DNS
              row. Weigh the domain-level findings instead.
            </div>
          </Section>

          <Section id="scoring">
            <h2 className={h2}>How the score works</h2>
            <p className={body}>
              Every Fail or Warn finding adds points by how serious it is. A Fail counts {FAIL_MULTIPLIER} times as much as a Warn.
              The total is capped at 100.
            </p>
            <div className="oa-tablewrap">
              <table className="oa-table oa-stack min-w-[520px]">
                <thead>
                  <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Warn adds</th>
                    <th scope="col">Fail adds</th>
                  </tr>
                </thead>
                <tbody>
                  {(['critical', 'high', 'medium', 'low'] as RiskLevel[]).map((s) => (
                    <tr key={s}>
                      <td className="font-semibold text-ink">{levelWord(s)}</td>
                      <td className={`${mono} text-ink-body`}>{SEVERITY_POINTS[s]}</td>
                      <td className={`${mono} text-ink-body`}>{SEVERITY_POINTS[s] * FAIL_MULTIPLIER}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className={body}>
              Blocklists are folded into one Blocklist coverage finding first. Each listing counts with its source&apos;s trust
              weight, combined as 1 − Π(1 − weight) into a 0–100 blocklist score, so one listing on a curated list outweighs
              several hits on aggressive ones.
            </p>
            <div className="oa-tablewrap">
              <table className="oa-table oa-stack min-w-[520px]">
                <thead>
                  <tr>
                    <th scope="col" className="w-[110px]">Weight</th>
                    <th scope="col">Sources</th>
                    <th scope="col" className="w-[180px]">Why</th>
                  </tr>
                </thead>
                <tbody>
                  {(['high', 'medium', 'low', 'noisy'] as BlocklistTrust[]).map((t) => (
                    <tr key={t}>
                      <td className="font-semibold text-ink">
                        {t.charAt(0).toUpperCase() + t.slice(1)} <span className={`${mono} font-normal text-muted`}>{TRUST_WEIGHT[t]}</span>
                      </td>
                      <td className="text-ink-body">{tiers[t].join(', ')}</td>
                      <td className="text-muted">{TIER_WHY[t]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className={body}>
              The blocklist score becomes a{' '}
              {COVERAGE_THRESHOLDS.map((b, i) => (
                <span key={b.min}>
                  {i > 0 && (i === COVERAGE_THRESHOLDS.length - 1 ? ' or ' : ', ')}
                  {b.status === 'fail' ? 'Fail' : 'Warn'} of {b.severity} severity at {b.min === 1 ? 'anything above 0' : `${b.min} or more`}
                </span>
              ))}
              . A Spamhaus residential (PBL) listing is policy, not abuse, and doesn&apos;t count.
            </p>
            <div className="oa-g2 grid grid-cols-4 gap-2">
              {RISK_BANDS.map((b) => (
                <div key={b.level} className="flex flex-col gap-[2px] rounded border border-line px-[14px] py-3">
                  <span className={`font-semibold ${LEVEL_INK[b.level]}`}>
                    <span className={`oa-dot ${b.level === 'low' ? 'pass' : b.level === 'medium' ? 'warn' : 'fail'}`} />
                    {levelWord(b.level)}
                  </span>
                  <span className={`${mono} text-muted`}>{b.min} to {b.max}</span>
                </div>
              ))}
            </div>
            <p className={body}>
              <strong className="text-ink">Confidence</strong> is separate from the score: it is the share of findings that came
              from a source that actually answered. It drops when sources are skipped, so a 90 with 40% confidence means
              &quot;probably bad, but most checks didn&apos;t run&quot;.
            </p>
          </Section>

          <Section id="bulk">
            <h2 className={h2}>
              Bulk checks <span className="ml-2 text-[13px] font-medium text-muted [font-stretch:100%]">logged in</span>
            </h2>
            <p className={body}>
              Paste a list, one target per line, or upload a CSV. A column named <span className={mono}>ip</span>,{' '}
              <span className={mono}>domain</span>, <span className={mono}>target</span> or <span className={mono}>url</span> is
              picked up automatically; otherwise the first column is used.
            </p>
            <ul className="m-0 flex list-disc flex-col gap-[6px] pl-[18px] text-ink-body">
              <li>Private and reserved IPs are removed before anything is looked up, and listed as skipped in the export.</li>
              <li>Duplicates are collapsed. Anything checked in the last 24 hours is reused unless you turn that off.</li>
              <li>
                Jobs take up to {BULK_MAX_TARGETS} IPs or domains, one running job per account. Rate limits are respected per key, so
                VirusTotal runs at {VT_PER_MINUTE} a minute. &quot;Free sources only&quot; skips every keyed source and finishes{' '}
                {BULK_MAX_TARGETS} targets in about {minutesFreeOnly(BULK_MAX_TARGETS)} minutes.
              </li>
              <li>
                Bulk jobs only use your own keys, and skip WHOIS (it runs on a shared server quota). Jobs can be paused, resumed or
                cancelled; they are kept for 7 days.
              </li>
              <li>
                Export is a CSV with one row per target: verdict, score, abuse score, VirusTotal detections, blocklist hits, proxy
                type, country, top finding. Import it into a SIEM watchlist such as FortiSIEM.
              </li>
            </ul>
          </Section>

          <Section id="keys">
            <h2 className={h2}>
              API keys <span className="ml-2 text-[13px] font-medium text-muted [font-stretch:100%]">logged in</span>
            </h2>
            <p className={body}>
              Most sources are free and need nothing. A few rate-limited ones work better with your own key, which you add once
              in <Link href="/settings">Settings</Link>. Keys are encrypted on the server and only used for your lookups; they are
              never pooled between accounts.
            </p>
            <div className="oa-tablewrap">
              <table className="oa-table oa-stack min-w-[520px]">
                <thead>
                  <tr>
                    <th scope="col">Service</th>
                    <th scope="col">Free tier</th>
                    <th scope="col">Without a key</th>
                  </tr>
                </thead>
                <tbody>
                  {SERVICES.map((s) => (
                    <tr key={s.id}>
                      <td className="text-ink">{s.name}</td>
                      <td className="text-ink-body">{s.freeTier}</td>
                      <td className="text-muted">
                        {s.id === 'spamhaus_dqs' ? 'Public mirror, may refuse' : "Skipped (single checks use the server's key if it has one)"}
                      </td>
                    </tr>
                  ))}
                  <tr>
                    <td className="text-ink">{serverOnly.map((s) => s.name).join(', ')}</td>
                    <td className="text-ink-body">Server key only</td>
                    <td className="text-muted">Skipped unless the server admin sets one</td>
                  </tr>
                  <tr>
                    <td className="text-ink">
                      {keyless.filter((s) => s.kind !== 'dnsbl').map((s) => s.name).join(', ')}, and{' '}
                      {SOURCES.filter((s) => s.kind === 'dnsbl' && s.id !== 'btc-black').length} DNSBLs
                    </td>
                    <td className="text-ink-body">No key needed</td>
                    <td className="text-muted">Always run</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <details id="sources" className="rounded border border-line px-4 py-3 text-[14px]">
              <summary className="cursor-pointer text-ink">All {SOURCE_COUNT} sources</summary>
              <ul className="m-0 mt-3 grid list-none grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-x-6 gap-y-1 p-0 text-ink-body">
                {SOURCES.map((s) => (
                  <li key={s.id}>
                    {s.name}
                    {s.service ? <span className="text-faint"> (key)</span> : s.serverKeyEnv ? <span className="text-faint"> (server key)</span> : ''}
                  </li>
                ))}
              </ul>
            </details>
          </Section>

          <Section id="privacy">
            <h2 className={h2}>Privacy and limits</h2>
            <ul className="m-0 flex list-disc flex-col gap-[6px] pl-[18px] text-ink-body">
              <li>
                The target you paste is sent to the sources listed on its result and nowhere else. Logged-out checks are not written
                to disk. Logged-in users see their recent targets for 7 days (targets only); bulk results are kept 24 hours so they
                can be reused, and jobs for 7 days.
              </li>
              <li>Shared links contain the result data in the link itself, after the #, so they work without us storing anything.</li>
              <li>
                Public, logged-out checks use the server&apos;s own keys and are limited to {ANONYMOUS_CHECKS_PER_HOUR} an hour per
                visitor. DNS blocklists get {DNSBL_TIMEOUT_SECONDS} seconds to answer, everything else {SOURCE_TIMEOUT_SECONDS}.
              </li>
              <li>A clean result means nobody has reported it yet. New scam infrastructure is often clean for its first few days.</li>
              <li>This is a student-built tool. It is useful for triage and not a substitute for your organisation&apos;s security team.</li>
            </ul>
          </Section>
        </main>
      </div>
    </PageChrome>
  );
}
