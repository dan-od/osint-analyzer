import Link from 'next/link';
import PageChrome from '@/components/chrome/PageChrome';
import { DataColumn, MarkBleed, SOURCE_LINES } from '@/components/decor';
import { IP_DNSBL_COUNT, SOURCE_COUNT } from '@/lib/source-catalog';
import { DNSBL_TIMEOUT_SECONDS, SOURCE_TIMEOUT_SECONDS, TYPICAL_CHECK_SECONDS } from '@/lib/bulk-limits';

export const metadata = { title: 'Features · OSINT Analyzer' };

const MODULES: { title: string; tag: string; text: string; points: string[]; sources: string }[] = [
  {
    title: 'Email intelligence',
    tag: 'EMAIL',
    text: 'Is the address real, and is the domain behind it set up to be spoofed?',
    points: ['Mailbox exists and accepts mail', 'Fraud score and recent abuse', 'Disposable and honeypot detection', 'Breach history', 'MX, SPF and DMARC', 'Domain age and registrar'],
    sources: 'IPQualityScore, Hunter.io, HIBP, EmailRep, DNS, WHOIS, Spamhaus DBL',
  },
  {
    title: 'Domain and URL analysis',
    tag: 'DOMAIN',
    text: 'Registration, DNS, reputation and whether it is pretending to be someone else.',
    points: ['Registration date and age', 'DNS records and CDN detection', 'Phishing and malware feeds', 'Google Safe Browsing', 'Domain blocklists (DBL, SURBL, URIBL)', 'Look-alike and suspicious-TLD rules'],
    sources: 'VirusTotal, URLhaus, ThreatFox, PhishTank, OpenPhish, PhishStats, Spamhaus, SURBL, URIBL, OTX',
  },
  {
    title: 'IP reputation',
    tag: 'IP',
    text: 'The same checks a SOC runs by hand on a suspicious source address, in one go.',
    points: ['Abuse confidence and report count', `${IP_DNSBL_COUNT} DNS blocklists, weighted`, 'VPN, proxy, Tor and datacenter', 'Open ports and known CVEs', 'Mass scanner or targeted', 'Daily feeds: Feodo, Tor exits, FireHOL'],
    sources: 'AbuseIPDB, VirusTotal, GreyNoise, Shodan, Spamhaus, IP2Proxy, abuse.ch, OTX',
  },
  {
    title: 'Phone lookup',
    tag: 'PHONE',
    text: 'Who owns the number, what kind of line it is, and whether others have reported it.',
    points: ['Carrier and region', 'Mobile, landline or VoIP', 'Spam and fraud reports', 'Premium-rate and callback traps'],
    sources: 'IPQualityScore, NumVerify',
  },
  {
    title: 'Crypto wallet screening',
    tag: 'WALLET',
    text: 'Has this address been named in a scam, a ransomware payout, or a sanctions list?',
    points: ['Community scam reports', 'Ransomware payment addresses', 'OFAC sanctions lists', 'Known scam wallet lists'],
    sources: 'ChainAbuse, BTC Black, OpenSanctions, Chainalysis, GitHub lists',
  },
  {
    title: 'Scoring and guidance',
    tag: 'ENGINE',
    text: 'Every finding is weighted by how serious it is, and every blocklist by how much it can be trusted, then turned into advice.',
    points: ['Four blocklist trust tiers, documented', 'Score bands: Low, Medium, High, Critical', 'Confidence drops when sources are skipped', 'Recommended next steps per verdict', 'Shareable link and JSON export'],
    sources: 'See the docs for the exact weights',
  },
];

const STEPS: { n: string; title: string; text: string }[] = [
  { n: '01', title: 'Detect', text: 'Work out whether it is an IP, domain, URL, email, phone or wallet. Normalise it. Drop anything private.' },
  {
    n: '02',
    title: 'Query',
    text: `Ask every source for that type at the same time. DNS blocklists get ${DNSBL_TIMEOUT_SECONDS} seconds each, everything else ${SOURCE_TIMEOUT_SECONDS}. Bulk jobs reuse anything checked in the last 24 hours.`,
  },
  { n: '03', title: 'Weigh', text: 'Score each finding by severity and each blocklist by reliability. Note what was skipped and lower confidence accordingly.' },
  { n: '04', title: 'Report', text: 'A verdict, the findings table with every source named, next steps, and a link you can hand to someone.' },
];

export default function FeaturesPage() {
  const stats = [
    { value: String(SOURCE_COUNT), label: 'sources' },
    { value: `${TYPICAL_CHECK_SECONDS.min}–${TYPICAL_CHECK_SECONDS.max} s`, label: 'typical full check' },
    { value: String(IP_DNSBL_COUNT), label: 'live DNS blocklists' },
    { value: '0', label: 'public check results stored' },
  ];

  return (
    <PageChrome>
      <section aria-label="Features title" className="oa-dots relative overflow-hidden border-b border-line">
        <MarkBleed size={420} style={{ right: -80, top: -100 }} />
        <div className="oa-sec oa-wrap relative box-border flex min-h-[480px] flex-col justify-center gap-[22px] pb-16 pt-20">
          <h1 className="oa-h1 oa-display max-w-[16ch] text-[56px] leading-none">
            Six modules. <span className="text-accent">One verdict.</span>
          </h1>
          <p className="m-0 max-w-[56ch] text-[18px] text-ink-body">
            Each kind of target gets its own set of checks against its own sources. The scoring engine weighs them and tells you
            what it found and what to do.
          </p>
          <div className="oa-g2 mt-[10px] grid max-w-[760px] grid-cols-4 gap-3">
            {stats.map((s) => (
              <div key={s.label} className="flex flex-col gap-[2px] rounded border border-line bg-panel px-4 py-[14px]">
                <span className="whitespace-nowrap font-mono text-[clamp(20px,5.5vw,26px)] text-ink-strong">{s.value}</span>
                <span className="text-[13px] text-muted">{s.label}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section aria-label="Modules" className="relative overflow-hidden border-b border-line">
        <DataColumn lines={SOURCE_LINES} />
        <div className="oa-wrap relative flex flex-col gap-7 py-[72px]">
          <h2 className="oa-h2 oa-display text-[34px] leading-[1.05]">
            What each module <span className="text-accent">looks at</span>
          </h2>
          <div className="oa-g1 grid grid-cols-3 gap-4">
            {MODULES.map((m) => (
              <div key={m.tag} className="flex min-w-0 flex-col gap-[14px] rounded border border-line bg-panel p-6">
                <div className="flex items-baseline justify-between gap-3">
                  <h3 className="oa-display text-[20px]">{m.title}</h3>
                  <span className="whitespace-nowrap font-mono text-[11px] text-muted">{m.tag}</span>
                </div>
                <p className="m-0 text-[14px] text-muted">{m.text}</p>
                <ul className="m-0 flex list-none flex-col gap-[6px] p-0">
                  {m.points.map((p) => (
                    <li key={p} className="flex items-start gap-[10px] text-[14px] text-ink-body">
                      <span className="mt-[7px] h-[6px] w-[6px] flex-none rounded-full bg-accent" />
                      <span>{p}</span>
                    </li>
                  ))}
                </ul>
                <span className="mt-auto border-t border-line pt-[6px] text-[12px] text-faint">{m.sources}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section aria-label="From paste to verdict" className="relative overflow-hidden border-b border-line">
        <MarkBleed size={420} style={{ left: -90, bottom: -110 }} />
        <div className="oa-sec oa-wrap relative box-border flex min-h-[560px] flex-col justify-center gap-7 py-[72px]">
          <h2 className="oa-h2 oa-display text-[34px] leading-[1.05]">
            From paste to <span className="text-accent">verdict</span>
          </h2>
          <div className="oa-g2 grid grid-cols-4 overflow-hidden rounded border border-line">
            {STEPS.map((s, i) => (
              <div key={s.n} className={`flex min-w-0 flex-col gap-2 p-[22px] ${i < STEPS.length - 1 ? 'border-r border-line' : ''}`}>
                <span className={`font-mono text-[12px] ${i === 0 ? 'text-accent' : 'text-muted'}`}>{s.n}</span>
                <h3 className="m-0 text-[17px] font-semibold">{s.title}</h3>
                <p className="m-0 text-[14px] text-muted">{s.text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section aria-label="Try it" className="oa-dots">
        <div className="oa-sec oa-wrap box-border flex min-h-[360px] flex-wrap items-center justify-between gap-x-12 gap-y-6 py-[72px]">
          <div className="flex max-w-[56ch] flex-col gap-2">
            <h2 className="oa-h2 oa-display text-[34px] leading-[1.05]">Got something suspicious right now?</h2>
            <p className="m-0 text-muted">No account needed for a single check. Teams can log in for bulk jobs and their own keys.</p>
          </div>
          <div className="flex flex-wrap gap-[10px]">
            <Link href="/" className="oa-btn-primary h-auto px-[22px] py-[14px]">Check something</Link>
            <Link href="/login" className="oa-btn-outline px-5 py-[14px]">Log in</Link>
          </div>
        </div>
      </section>
    </PageChrome>
  );
}
