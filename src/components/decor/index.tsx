// Section backgrounds and box details from the mockups: the large faint mark
// bleeding off a corner, the slowly scrolling mono data column, corner ticks.
import { Fragment, type CSSProperties } from 'react';
import { SweepMark } from '@/components/brand/Logo';
import { DOMAIN_DNSBL_META, FEED_META, IP_DNSBL_META } from '@/lib/blocklist-meta';

/** Faint logo mark bleeding off a corner of a section */
export function MarkBleed({ size = 340, opacity = 0.06, style }: { size?: number; opacity?: number; style: CSSProperties }) {
  return (
    <SweepMark
      size={size}
      strokeWidth={1.2}
      style={{ position: 'absolute', opacity, pointerEvents: 'none', ...style }}
    />
  );
}

/** Four small L-shaped corners. Accent for the hero card, sign-up card and drop zone. */
export function CornerTicks({ tone = 'muted' }: { tone?: 'muted' | 'accent' }) {
  const color = tone === 'accent' ? '#F28C28' : '#4A525B';
  const base: CSSProperties = { position: 'absolute', width: 10, height: 10, pointerEvents: 'none' };
  const line = `1.5px solid ${color}`;
  return (
    <>
      <span aria-hidden="true" style={{ ...base, left: 6, top: 6, borderLeft: line, borderTop: line }} />
      <span aria-hidden="true" style={{ ...base, right: 6, top: 6, borderRight: line, borderTop: line }} />
      <span aria-hidden="true" style={{ ...base, left: 6, bottom: 6, borderLeft: line, borderBottom: line }} />
      <span aria-hidden="true" style={{ ...base, right: 6, bottom: 6, borderRight: line, borderBottom: line }} />
    </>
  );
}

/** Slowly scrolling column of mono text on the right of a section. Hidden on phones. */
export function DataColumn({ lines }: { lines: string[] }) {
  // Rendered twice so the -50% scroll loops seamlessly
  const doubled = [...lines, ...lines];
  return (
    <div aria-hidden="true" className="oa-datacol">
      <div>
        {doubled.map((line, i) => (
          <Fragment key={i}>
            {line}
            <br />
          </Fragment>
        ))}
      </div>
    </div>
  );
}

const FEED_HOSTS = FEED_META.map((f) => new URL(f.url).hostname);
const SOURCE_HOSTS = [
  'api.abuseipdb.com',
  'urlhaus-api.abuse.ch',
  'threatfox-api.abuse.ch',
  'otx.alienvault.com',
  'api.greynoise.io',
  'internetdb.shodan.io',
  'openphish.com',
  'checkurl.phishtank.com',
];

function interleave(a: string[], b: string[], every: number): string[] {
  const out: string[] = [];
  let j = 0;
  a.forEach((item, i) => {
    out.push(item);
    if ((i + 1) % every === 0 && j < b.length) out.push(b[j++]);
  });
  return out;
}

/** The zones and hosts we actually query */
export const SOURCE_LINES = interleave(
  [...IP_DNSBL_META.slice(0, 8).map((m) => m.zone), ...DOMAIN_DNSBL_META.slice(0, 3).map((m) => m.zone), ...IP_DNSBL_META.slice(8, 14).map((m) => m.zone)],
  [...SOURCE_HOSTS, ...FEED_HOSTS],
  2
);

/** Sources mixed with reserved documentation addresses (never real ones) */
export const SOURCE_AND_IP_LINES = interleave(
  SOURCE_LINES,
  ['203.0.113.77', '198.51.100.9', '203.0.113.42', '192.0.2.46', '192.0.2.18', '198.51.100.24', '203.0.113.5', '198.51.100.71'],
  3
);

/** DNS-looking records, all reserved names and addresses */
export const DNS_LINES = [
  'v=spf1 ~all', 'MX 10 mail1', 'A 198.51.100.24', 'NS ns1.example', 'DMARC missing', 'TXT site-verify',
  'AAAA 2001:db8::1', 'CNAME cdn', 'SOA 2026100501', 'MX 20 mail2', 'A 198.51.100.7', 'TXT v=DKIM1',
  'PTR exit.example', 'NS ns2.example', 'A 198.51.100.9', 'TXT _dmarc=none', 'CAA 0 issue', 'A 203.0.113.77',
  'MX 5 mx.example', 'TXT spf include', 'A 192.0.2.18', 'NS ns3.example', 'A 192.0.2.46', 'DMARC p=reject',
];
