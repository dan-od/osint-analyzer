// Is an address part of a CDN? If so, IP-level reputation describes the CDN,
// not the site behind it. Ranges are the providers' published lists
// (cloudflare.com/ips-v4, /ips-v6 and api.fastly.com/public-ip-list, Oct 2026).
import { parseCidr, parseIp, type CidrRange } from '@/lib/ip';

const CDN_RANGES: Record<string, string[]> = {
  Cloudflare: [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
    '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
    '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
    '2a06:98c0::/29', '2c0f:f248::/32',
  ],
  Fastly: [
    '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '103.245.222.0/23', '103.245.224.0/24',
    '104.156.80.0/20', '140.248.64.0/18', '140.248.128.0/17', '146.75.0.0/17', '151.101.0.0/16',
    '157.52.64.0/18', '167.82.0.0/17', '167.82.128.0/20', '167.82.160.0/20', '167.82.224.0/20',
    '172.111.64.0/18', '185.31.16.0/22', '199.27.72.0/21', '199.232.0.0/16',
    '2a04:4e40::/32', '2a04:4e42::/32',
  ],
};

const RANGES: { provider: string; range: CidrRange }[] = Object.entries(CDN_RANGES).flatMap(([provider, cidrs]) =>
  cidrs.map((cidr) => ({ provider, range: parseCidr(cidr)! }))
);

/** CDN provider name for an address, or null */
export function cdnForIp(address: string): string | null {
  const ip = parseIp(address);
  if (!ip) return null;
  const hit = RANGES.find(
    ({ range }) => range.version === ip.version && ip.value >= range.start && ip.value <= range.end
  );
  return hit?.provider ?? null;
}
