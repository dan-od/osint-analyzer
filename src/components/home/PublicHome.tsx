import Link from 'next/link';
import CheckForm from '@/components/check/CheckForm';
import { CornerTicks, DataColumn, DNS_LINES, MarkBleed, SOURCE_AND_IP_LINES } from '@/components/decor';
import { IP_DNSBL_COUNT, SOURCE_COUNT, sourceCountFor } from '@/lib/source-catalog';
import type { AnalysisType } from '@/types';

/* Sample content on this page uses reserved names and numbers only
   (.example, 203.0.113.x / 198.51.100.x / 192.0.2.x, 555 numbers). */

const TICKER: { target: string; level: 'Low' | 'Medium' | 'High' | 'Critical' }[] = [
  { target: '203.0.113.77', level: 'High' },
  { target: 'okoro.me', level: 'Low' },
  { target: 'manager@wfsl.example', level: 'Critical' },
  { target: 'cdn-assets-update.example', level: 'Medium' },
  { target: '+1 416 555 0100', level: 'Low' },
  { target: '198.51.100.9', level: 'Critical' },
  { target: 'bc1q9x…k2d', level: 'Medium' },
  { target: '192.0.2.46', level: 'Low' },
];

const LEVEL_INK = { Low: 'text-pass-ink', Medium: 'text-warn', High: 'text-fail-ink', Critical: 'text-fail-ink' };

const CHECKS: { type: AnalysisType; example: string; title: string; text: string; chips: string[] }[] = [
  {
    type: 'ip',
    example: '203.0.113.42',
    title: 'IP address',
    text: 'Where it is, who owns it, and whether anyone has reported it.',
    chips: ['Abuse reports', `${IP_DNSBL_COUNT} blocklists`, 'VPN / Tor', 'Open ports', 'Scanner noise'],
  },
  {
    type: 'domain',
    example: 'example-login.example',
    title: 'Website',
    text: 'How old it is and whether it is on any phishing or malware list.',
    chips: ['Domain age', 'Phishing feeds', 'Malware feeds', 'Safe Browsing', 'Look-alikes'],
  },
  {
    type: 'email',
    example: 'ceo@pay-now.example',
    title: 'Email',
    text: 'Does the mailbox exist, and can the domain be spoofed?',
    chips: ['Mailbox exists', 'Fraud score', 'Breaches', 'SPF / DMARC', 'Disposable'],
  },
  {
    type: 'phone',
    example: '+1 416 555 0100',
    title: 'Phone',
    text: 'Which carrier, what kind of line, and who else has flagged it.',
    chips: ['Carrier', 'VoIP', 'Spam reports', 'Premium-rate'],
  },
  {
    type: 'crypto',
    example: 'bc1q9x…k2d',
    title: 'Crypto wallet',
    text: 'Named in a scam, a ransomware payout, or a sanctions list?',
    chips: ['Scam reports', 'Ransomware', 'Sanctions'],
  },
];

const chip = 'rounded bg-raised px-[9px] py-[5px] text-[13px] text-ink-body';

export default function PublicHome() {
  return (
    <>
      {/* Hero: dot grid + data column */}
      <section aria-label="Check something" className="oa-dots relative overflow-hidden border-b border-line">
        <DataColumn lines={SOURCE_AND_IP_LINES} />
        <div className="oa-sec oa-full-hero oa-wrap relative box-border flex flex-wrap items-center gap-x-16 gap-y-12 pb-[72px] pt-20">
          <div className="flex min-w-0 flex-[999_1_460px] flex-col gap-6">
            <h1 className="oa-h1 oa-display text-[64px] leading-[0.98] tracking-[-0.01em] [text-wrap:balance]">
              That email, link or number looks off? <span className="text-accent">Paste it here.</span>
            </h1>
            <p className="m-0 max-w-[52ch] text-[18px] text-ink-body">
              We run it past {SOURCE_COUNT} blocklists, abuse databases and reputation checks and tell you in plain words whether
              it&apos;s a scam. Takes a few seconds. Nothing is stored.
            </p>
            <CheckForm variant="home" />
            <div className="flex flex-wrap items-center gap-x-[18px] gap-y-[6px] text-[14px] text-muted">
              <span>No sign-up needed.</span>
              <span>
                Try one:{' '}
                <Link href="/results?q=manager%40wfsl.example" className="font-mono">
                  manager@wfsl.example
                </Link>
              </span>
              <span>
                <Link href="/results?q=203.0.113.77" className="font-mono">
                  203.0.113.77
                </Link>
              </span>
            </div>
          </div>

          <div role="group" aria-label="Example verdicts" className="oa-tiltwrap relative flex min-h-[330px] min-w-0 max-w-[420px] flex-[1_1_340px] items-center justify-center">
            <div className="oa-tilt absolute flex w-[86%] max-w-[360px] flex-col gap-2 rounded border border-line bg-panel px-5 py-[18px] opacity-90 [transform:rotate(3deg)_translate(28px,-58px)]">
              <span className="inline-flex items-center gap-2 text-[13px] font-semibold text-pass-ink">
                <span className="oa-dot pass !mr-0" />
                Low risk, 0 / 100
              </span>
              <span className="font-mono text-[18px] text-ink-strong">okoro.me</span>
              <span className="text-[13px] text-muted">Clean on every source that answered. Registered 3 years, no reports.</span>
            </div>
            <div className="oa-tilt relative flex w-full max-w-[380px] flex-col gap-3 rounded border border-line-strong bg-panel px-6 py-[22px] shadow-[0_24px_48px_rgba(0,0,0,0.45)] [transform:rotate(-2deg)]">
              <CornerTicks tone="accent" />
              <div className="flex items-center justify-between gap-3">
                <span className="oa-badge fail">
                  <span className="oa-dot fail" />
                  Critical risk
                </span>
                <span className="font-mono text-[26px] leading-none text-fail-ink">
                  98<span className="text-[13px] text-muted"> / 100</span>
                </span>
              </div>
              <span className="break-all font-mono text-[20px] text-ink-strong">manager@wfsl.example</span>
              <p className="m-0 text-[14px] text-ink-body">Fraud score 91 and the mailbox doesn&apos;t exist. Don&apos;t reply, don&apos;t pay.</p>
              <div className="mt-[2px] flex flex-wrap gap-[6px]">
                <span className="rounded bg-fail-bg px-2 py-1 text-[12px] text-fail-ink">Fraud score</span>
                <span className="rounded bg-fail-bg px-2 py-1 text-[12px] text-fail-ink">Undeliverable</span>
                <span className="rounded bg-warn-bg px-2 py-1 text-[12px] text-warn">No DMARC</span>
                <span className="rounded bg-raised px-2 py-1 text-[12px] text-muted">+3 passed</span>
              </div>
            </div>
          </div>
        </div>

        {/* Ticker: reserved example data only, never real lookups */}
        <div aria-hidden="true" className="oa-ticker relative overflow-hidden whitespace-nowrap border-t border-line bg-foot py-[10px] text-[13px] text-muted">
          <span className="absolute left-5 top-[10px] z-[1] bg-foot pr-[14px] text-faint">
            <span className="mr-2 inline-block h-[7px] w-[7px] rounded-full bg-accent" style={{ animation: 'oa-pulse 1.4s infinite' }} />
            Checked just now
          </span>
          <div className="inline-block pl-[170px]">
            {[...TICKER, ...TICKER].map((t, i) => (
              <span key={i} className="mr-9">
                <span className="font-mono">{t.target}</span> <span className={LEVEL_INK[t.level]}>{t.level}</span>
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how-it-works" aria-label="How it works" className="relative overflow-hidden border-b border-line">
        <MarkBleed size={420} style={{ left: -90, bottom: -110 }} />
        <div className="oa-sec oa-full oa-wrap relative box-border flex flex-col justify-center gap-7 py-[72px]">
          <h2 className="oa-h2 oa-display text-[34px] leading-[1.05]">
            Three steps, no accounts, <span className="text-accent">no homework.</span>
          </h2>
          <div className="oa-g1 grid grid-cols-3 gap-5">
            <StepCard
              n="01"
              title="Paste the thing"
              text="A link from a text, the email that asked for gift cards, the number that keeps calling. We work out what it is."
              accent
            >
              <div className="flex gap-[6px]">
                <span className="flex h-[38px] flex-auto items-center overflow-hidden whitespace-nowrap rounded border border-line-strong bg-ground px-3 font-mono text-[13px] text-ink">
                  short.example/3xK9…{' '}
                  <span className="ml-[2px] inline-block h-[14px] w-px bg-accent" style={{ animation: 'oa-pulse 1s infinite' }} />
                </span>
                <span className="inline-flex h-[38px] items-center whitespace-nowrap rounded border border-line-strong px-3 text-[12px] text-muted">URL</span>
              </div>
            </StepCard>
            <StepCard
              n="02"
              title="We ask around"
              text="Blocklists, abuse reports, DNS, breach data, fraud scoring. The same sources security teams use, queried at once."
            >
              <div className="flex flex-col gap-[6px] font-mono text-[12px]">
                <div className="flex justify-between text-muted"><span>Spamhaus</span><span className="text-pass-ink">clean</span></div>
                <div className="flex justify-between text-muted"><span>URLhaus</span><span className="text-fail-ink">listed</span></div>
                <div className="flex justify-between text-muted"><span>Safe Browsing</span><span className="text-fail-ink">malware</span></div>
                <div className="flex justify-between text-faint">
                  <span>VirusTotal</span>
                  <span><span className="inline-block h-[6px] w-[6px] rounded-full bg-accent" style={{ animation: 'oa-pulse 1.2s infinite' }} /></span>
                </div>
              </div>
            </StepCard>
            <StepCard
              n="03"
              title="You get a straight answer"
              text="A verdict, a score, and what to do next. The evidence is there if you want it. Share it with a link."
            >
              <div className="flex items-center justify-between">
                <span className="oa-badge fail !text-[12px]">
                  <span className="oa-dot fail !h-[7px] !w-[7px]" />
                  High risk
                </span>
                <span className="font-mono text-[22px] leading-none text-fail-ink">82</span>
              </div>
              <span className="text-[13px] text-ink-body">Known malware link. Don&apos;t open it.</span>
            </StepCard>
          </div>
        </div>
      </section>

      {/* What we check */}
      <section aria-label="What we check" className="relative overflow-hidden border-b border-line">
        <DataColumn lines={DNS_LINES} />
        <div className="oa-sec oa-full oa-wrap relative box-border flex flex-col justify-center gap-6 py-[72px]">
          <div className="flex flex-wrap items-baseline gap-x-4 gap-y-[6px]">
            <h2 className="oa-h2 oa-display text-[34px] leading-[1.05]">
              What we <span className="text-accent">check</span>
            </h2>
            <span className="text-[15px] text-muted">
              Five kinds of target, {SOURCE_COUNT} sources. <Link href="/docs#input-types">Full list in the docs</Link>.
            </span>
          </div>
          <div className="oa-g1 grid grid-cols-3 gap-4">
            {CHECKS.map((c) => (
              <div key={c.type} className="oa-card box-border flex min-h-[250px] min-w-0 flex-col gap-3 rounded border border-line p-[26px]">
                <span className="flex h-[42px] items-center overflow-hidden whitespace-nowrap rounded border border-line-strong bg-panel px-[14px] font-mono text-[14px] text-accent">
                  {c.example}
                </span>
                <h3 className="m-0 text-[20px] font-semibold">{c.title}</h3>
                <p className="m-0 text-[15px] text-muted">{c.text}</p>
                <div className="flex flex-wrap gap-1">
                  {c.chips.map((label) => (
                    <span key={label} className={chip}>{label}</span>
                  ))}
                </div>
                <span className="mt-auto text-[12px] text-faint">{sourceCountFor(c.type)} sources</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* For teams */}
      <section aria-label="For security teams" className="oa-dots">
        <div className="oa-sec oa-full-short oa-wrap box-border flex flex-col justify-center py-[72px]">
          <div className="relative flex flex-wrap items-center gap-x-12 gap-y-7 overflow-hidden rounded border border-line bg-panel p-8">
            <MarkBleed size={360} opacity={0.07} style={{ right: -70, bottom: -90 }} />
            <div className="relative flex min-w-0 flex-[999_1_380px] flex-col gap-[10px]">
              <h2 className="oa-display text-[28px] leading-[1.05]">
                Running a SOC or a <span className="text-accent">team rotation?</span>
              </h2>
              <p className="m-0 max-w-[52ch] text-[15px] text-muted">
                Create a free account for bulk checks straight from a SIEM export, CSV back out with a verdict column, and your own API keys
                with quotas nobody else can burn.
              </p>
              <div className="mt-2">
                <Link href="/login" className="oa-btn-primary h-auto px-5 py-3">
                  Log in or create an account
                </Link>
              </div>
            </div>
            <div className="relative flex min-w-0 max-w-[380px] max-[720px]:max-w-none flex-[1_1_300px] flex-col gap-2 rounded border border-line bg-ground p-[14px] text-[12px]">
              <CornerTicks />
              <div className="flex justify-between text-muted"><span>fortisiem-dns-oct03.csv</span><span>148 / 198</span></div>
              <div className="h-[3px] overflow-hidden rounded-[2px] bg-line"><div className="h-full w-3/4 bg-accent" /></div>
              <MiniRow target="198.51.100.9" level="Critical" />
              <MiniRow target="203.0.113.77" level="High" />
              <MiniRow target="cdn-assets-update.example" level="Medium" />
              <MiniRow target="192.0.2.46" level="Low" last />
            </div>
          </div>
        </div>
      </section>
    </>
  );
}

function StepCard({ n, title, text, accent, children }: { n: string; title: string; text: string; accent?: boolean; children: React.ReactNode }) {
  return (
    <div className="oa-card flex min-w-0 flex-col rounded border border-line bg-panel">
      <div className="box-border flex h-[170px] flex-col justify-end gap-2 px-[22px] pt-[22px]">{children}</div>
      <div className="mt-[18px] flex flex-col gap-2 border-t border-line px-[22px] pb-[22px] pt-5">
        <span className={`font-mono text-[12px] ${accent ? 'text-accent' : 'text-muted'}`}>{n}</span>
        <h3 className="m-0 text-[18px] font-semibold">{title}</h3>
        <p className="m-0 text-[14px] text-muted">{text}</p>
      </div>
    </div>
  );
}

function MiniRow({ target, level, last }: { target: string; level: keyof typeof LEVEL_INK; last?: boolean }) {
  return (
    <div className={`flex justify-between py-[6px] ${last ? '' : 'border-b border-line'}`}>
      <span className="font-mono text-ink">{target}</span>
      <span className={`${LEVEL_INK[level]} ${level === 'Low' ? '' : 'font-semibold'}`}>{level}</span>
    </div>
  );
}
