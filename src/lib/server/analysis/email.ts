// ============================================
// EMAIL ANALYSIS - every source runs in parallel as its own task
// ============================================
import type { AnalysisResult, Indicator } from '@/types';
import {
  performDnsLookup,
  checkEmailRep,
  checkWhois,
  verifyEmailHunter,
  checkIPQSEmail,
  checkHaveIBeenPwned,
  analyzeEmailPatterns,
  isDisposableEmail,
  hasSuspiciousTLD,
  type DnsResult,
  type EmailRepResult,
  type WhoisResult,
  type IPQSEmailResult,
  type HIBPResult,
} from '@/lib/osint-apis';
import type { BlocklistSourceResult } from '@/types';
import { checkDomainDnsbls } from '../blocklists/dnsbl';
import { dqsKey } from '../blocklists';
import type { AnalysisContext } from './context';
import { TaskRunner } from './tasks';
import { buildResult } from './scoring';
import { pivotsFor, withFacts } from './facts';

type HunterResult = NonNullable<Awaited<ReturnType<typeof verifyEmailHunter>>>;

export async function analyzeEmail(email: string, ctx: AnalysisContext): Promise<AnalysisResult> {
  const domain = email.split('@')[1];
  const runner = new TaskRunner(ctx);

  runner.add<DnsResult>({
    id: 'dns',
    label: 'MX, SPF and DMARC',
    source: 'DNS lookup',
    run: () => performDnsLookup(domain),
    build: (dns, out) => {
      out.indicators.push(
        {
          id: 'mx-records',
          name: 'MX records',
          status: dns.hasMx ? 'pass' : 'fail',
          description: dns.hasMx
            ? `Valid. ${dns.mx.map((m) => m.exchange).join(', ')}`
            : 'No MX records. The domain cannot receive email.',
          severity: dns.hasMx ? 'low' : 'critical',
          source: 'DNS lookup',
        },
        {
          id: 'spf-record',
          name: 'SPF record',
          status: dns.hasSpf ? 'pass' : 'warning',
          description: dns.hasSpf
            ? 'Present and configured for email authentication.'
            : `No SPF record on ${domain}. Mail from it can be spoofed more easily.`,
          severity: dns.hasSpf ? 'low' : 'medium',
          source: 'DNS lookup',
        },
        {
          id: 'dmarc-record',
          name: 'DMARC record',
          status: dns.hasDmarc ? 'pass' : 'warning',
          description: dns.hasDmarc
            ? 'Present. The domain tells receivers what to do with spoofed mail.'
            : `No DMARC record on ${domain}. The domain can be spoofed without rejection.`,
          severity: dns.hasDmarc ? 'low' : 'medium',
          source: 'DNS lookup',
        }
      );
      out.details.dns = {
        title: `DNS, ${domain}`,
        data: {
          A: dns.a.join(', ') || 'none',
          MX: dns.mx.map((m) => m.exchange).join(', ') || 'none',
          NS: dns.ns.join(', ') || 'none',
          SPF: dns.spf || 'missing',
          DMARC: dns.dmarc || 'missing',
        },
        status: dns.hasMx && dns.hasSpf ? 'pass' : 'warning',
      };
    },
  });

  runner.add<EmailRepResult>({
    id: 'emailrep',
    label: 'Email reputation',
    source: 'EmailRep.io',
    run: () => checkEmailRep(email),
    build: (rep, out) => {
      out.indicators.push({
        id: 'email-reputation',
        name: 'Email reputation',
        status: rep.reputation === 'high' ? 'pass' : rep.reputation === 'medium' ? 'warning' : rep.reputation === 'low' ? 'fail' : 'unknown',
        description: `Reputation ${rep.reputation}, ${rep.references} reference(s) found${rep.suspicious ? ', flagged as suspicious' : ''}.`,
        severity: rep.reputation === 'high' ? 'low' : rep.reputation === 'medium' ? 'medium' : 'high',
        source: 'EmailRep.io',
      });
      if (rep.suspicious) {
        out.indicators.push({
          id: 'suspicious-check',
          name: 'Suspicious activity',
          status: 'fail',
          description: 'Flagged as suspicious by EmailRep threat intelligence.',
          severity: 'high',
          source: 'EmailRep.io',
        });
      }
      if (rep.details.blacklisted) {
        out.indicators.push({
          id: 'blacklisted',
          name: 'Blacklist status',
          status: 'fail',
          description: 'The address is blacklisted.',
          severity: 'critical',
          source: 'EmailRep.io',
        });
      }
      out.details.emailRep = {
        title: 'EmailRep',
        data: {
          reputation: rep.reputation,
          suspicious: rep.suspicious,
          references: rep.references,
          blacklisted: rep.details.blacklisted,
          dataBreach: rep.details.dataBreach,
          freeProvider: rep.details.freeProvider,
          deliverable: rep.details.deliverable,
        },
        status: rep.suspicious ? 'fail' : rep.reputation === 'high' ? 'pass' : 'warning',
      };
    },
  });

  runner.add<HunterResult>({
    id: 'hunter',
    label: 'Deliverability',
    source: 'Hunter.io',
    service: 'hunter',
    run: ({ key }) => verifyEmailHunter(email, key!),
    build: (hunter, out) => {
      const deliverable = hunter.result === 'deliverable';
      out.indicators.push({
        id: 'email-deliverable',
        name: 'Deliverability',
        status: deliverable ? 'pass' : hunter.result === 'risky' ? 'warning' : 'fail',
        description: deliverable
          ? `Deliverable. The mailbox exists and accepts mail (verification score ${hunter.score} / 100).`
          : hunter.result === 'risky'
            ? `Risky. The mailbox may not exist or accept all mail (verification score ${hunter.score} / 100).`
            : `Undeliverable. The mailbox does not exist or rejects mail (verification score ${hunter.score} / 100).`,
        severity: deliverable ? 'low' : 'medium',
        source: 'Hunter.io',
      });
      if (hunter.gibberish) {
        out.indicators.push({
          id: 'gibberish-email',
          name: 'Gibberish address',
          status: 'warning',
          description: 'The address looks randomly generated.',
          severity: 'medium',
          source: 'Hunter.io',
        });
      }
      out.details.hunter = {
        title: 'Hunter.io',
        data: {
          result: hunter.result,
          score: hunter.score,
          gibberish: hunter.gibberish,
          disposable: hunter.disposable,
          webmail: hunter.webmail,
        },
        status: deliverable ? 'pass' : 'warning',
      };
    },
  });

  runner.add<WhoisResult>({
    id: 'whois',
    label: 'Domain age',
    source: 'WHOIS',
    serverKeyEnv: 'WHOISXML_API_KEY',
    run: () => checkWhois(domain),
    build: (whois, out) => {
      out.indicators.push(domainAgeIndicator(whois));
      out.details.whois = {
        title: `WHOIS, ${domain}`,
        data: {
          registrar: whois.registrar || 'unknown',
          created: whois.creationDate?.slice(0, 10) || 'unknown',
          age: whois.domainAge !== null ? `${whois.domainAge} days` : 'unknown',
        },
        status: whois.isNewDomain ? 'warning' : 'pass',
      };
    },
  });

  runner.add<BlocklistSourceResult>({
    id: 'spamhaus-dbl',
    label: 'Spamhaus DBL',
    source: 'Spamhaus',
    run: async () => {
      const key = await dqsKey(ctx);
      const [dbl] = await checkDomainDnsbls(domain, { spamhausDqsKey: key, only: ['spamhaus-dbl'] });
      return dbl;
    },
    build: (dbl, out) => {
      if (dbl.status === 'listed') {
        out.indicators.push({
          id: 'spamhaus-dbl',
          name: 'Spamhaus DBL',
          status: 'fail',
          description: `${domain} is listed: ${dbl.detail || 'spam or malicious domain'}.`,
          severity: 'critical',
          source: 'Spamhaus',
        });
      } else if (dbl.status === 'clean') {
        out.indicators.push({ id: 'spamhaus-dbl', name: 'Spamhaus DBL', status: 'pass', description: 'Not listed.', severity: 'low', source: 'Spamhaus' });
      } else {
        out.answered = false;
        out.indicators.push({
          id: 'skipped-spamhaus-dbl',
          name: 'Spamhaus DBL',
          status: 'unknown',
          description: dbl.detail ? `${dbl.detail.charAt(0).toUpperCase()}${dbl.detail.slice(1)}.` : 'No answer.',
          severity: 'low',
          source: 'Spamhaus',
        });
      }
    },
  });

  runner.add<IPQSEmailResult>({
    id: 'ipqs',
    label: 'Fraud score',
    source: 'IPQualityScore',
    service: 'ipqs',
    run: ({ key }) => checkIPQSEmail(email, key!),
    build: (ipqs, out) => {
      if (ipqs.honeypot) {
        out.indicators.push({
          id: 'honeypot',
          name: 'Honeypot',
          status: 'fail',
          description: 'This is a known spam-trap address.',
          severity: 'critical',
          source: 'IPQualityScore',
        });
      }
      const traits = [ipqs.recentAbuse && 'recently seen in abuse reports', ipqs.disposable && 'disposable provider', ipqs.leaked && 'found in leaks']
        .filter(Boolean)
        .join(', ');
      out.indicators.push({
        id: 'fraud-score',
        name: 'Fraud score',
        status: ipqs.fraudScore >= 75 ? 'fail' : ipqs.fraudScore >= 50 ? 'warning' : 'pass',
        description: `${ipqs.fraudScore} / 100.${traits ? ` ${traits.charAt(0).toUpperCase()}${traits.slice(1)}.` : ''}`,
        severity: ipqs.fraudScore >= 75 ? 'critical' : ipqs.fraudScore >= 50 ? 'medium' : 'low',
        source: 'IPQualityScore',
      });
      out.details.ipqs = {
        title: 'IPQualityScore',
        data: {
          'fraud score': ipqs.fraudScore,
          'recent abuse': ipqs.recentAbuse,
          disposable: ipqs.disposable,
          honeypot: ipqs.honeypot,
          valid: ipqs.valid,
          'first seen': ipqs.firstSeen || 'unknown',
        },
        status: ipqs.fraudScore >= 75 ? 'fail' : ipqs.fraudScore >= 50 ? 'warning' : 'pass',
      };
    },
  });

  runner.add<HIBPResult>({
    id: 'hibp',
    label: 'Breach history',
    source: 'HIBP',
    service: 'hibp',
    run: ({ key }) => checkHaveIBeenPwned(email, key!),
    build: (hibp, out) => {
      if (hibp.breached) {
        out.indicators.push({
          id: 'hibp-breach',
          name: 'Breach history',
          status: hibp.breachCount > 3 ? 'fail' : 'warning',
          description: `Found in ${hibp.breachCount} data breach(es): ${hibp.breaches.slice(0, 4).map((b) => b.name).join(', ')}.`,
          severity: hibp.breachCount > 3 ? 'high' : 'medium',
          source: 'HIBP',
        });
        out.details.hibp = {
          title: 'Have I Been Pwned',
          data: { breaches: hibp.breachCount, pastes: hibp.pasteCount, latest: hibp.breaches.slice(0, 5).map((b) => b.name).join(', ') },
          status: 'warning',
        };
      } else {
        out.indicators.push({ id: 'hibp-breach', name: 'Breach history', status: 'pass', description: 'Not found in any known breach.', severity: 'low', source: 'HIBP' });
      }
    },
  });

  runner.add<Indicator[]>({
    id: 'rules',
    label: 'Address patterns',
    source: 'Rules',
    sources: 0,
    run: async () => {
      const found: Indicator[] = [];
      if (isDisposableEmail(email)) {
        found.push({
          id: 'disposable-email',
          name: 'Disposable address',
          status: 'fail',
          description: 'This is a known disposable or temporary email service.',
          severity: 'high',
          source: 'Disposable list',
        });
      }
      if (hasSuspiciousTLD(domain)) {
        found.push({
          id: 'suspicious-tld',
          name: 'Suspicious TLD',
          status: 'warning',
          description: 'The domain uses a TLD commonly associated with spam.',
          severity: 'medium',
          source: 'TLD rules',
        });
      }
      const pattern = analyzeEmailPatterns(email);
      if (pattern.suspicious) {
        found.push({
          id: 'email-patterns',
          name: 'Suspicious patterns',
          status: pattern.score >= 50 ? 'fail' : 'warning',
          description: `${pattern.flags.slice(0, 2).join('; ')}.`,
          severity: pattern.score >= 50 ? 'high' : 'medium',
          source: 'Pattern rules',
        });
      }
      return found;
    },
    build: (found, out) => out.indicators.push(...found),
  });

  await runner.run(email, 'email', pivotsFor('email', email));
  const { indicators, details } = runner.collect();
  const result = buildResult('email', email, indicators, details, ctx);
  return withFacts(
    { ...result, pivots: pivotsFor('email', email) },
    { abuseScore: null, vtDetections: null, proxyType: null, country: null }
  );
}

export function domainAgeIndicator(whois: WhoisResult): Indicator {
  const days = whois.domainAge;
  const years = days !== null ? Math.floor(days / 365) : null;
  return {
    id: 'domain-age',
    name: 'Domain age',
    status: whois.isNewDomain ? 'warning' : days === null ? 'unknown' : 'pass',
    description:
      days === null
        ? 'Registration date not published.'
        : whois.isNewDomain
          ? `Registered ${days.toLocaleString('en-US')} days ago. New domains are common in scams.`
          : `Registered ${days.toLocaleString('en-US')} days ago${years ? ` (about ${years} year${years === 1 ? '' : 's'})` : ''}. Not a throwaway domain.`,
    severity: whois.isNewDomain ? 'high' : 'low',
    source: 'WHOIS',
  };
}
