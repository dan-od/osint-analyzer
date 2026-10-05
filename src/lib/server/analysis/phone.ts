// ============================================
// PHONE ANALYSIS - every source runs in parallel as its own task
// ============================================
import type { AnalysisResult } from '@/types';
import {
  checkPhone,
  checkIPQSPhone,
  checkPhoneSpamDatabases,
  type IPQSPhoneResult,
  type PhoneResult,
  type PhoneSpamResult,
} from '@/lib/osint-apis';
import type { AnalysisContext } from './context';
import { TaskRunner } from './tasks';
import { buildResult } from './scoring';
import { withFacts } from './facts';

export async function analyzePhone(phone: string, ctx: AnalysisContext): Promise<AnalysisResult> {
  const runner = new TaskRunner(ctx);

  runner.add<PhoneResult>({
    id: 'numverify',
    label: 'Line type',
    source: 'NumVerify',
    serverKeyEnv: 'NUMVERIFY_API_KEY',
    run: () => checkPhone(phone),
    build: (p, out) => {
      out.indicators.push({
        id: 'phone-valid',
        name: 'Valid number',
        status: p.valid ? 'pass' : 'fail',
        description: p.valid ? `Valid ${p.countryName || ''} number${p.location ? `, ${p.location}` : ''}.`.replace('  ', ' ') : 'Not a valid phone number.',
        severity: p.valid ? 'low' : 'high',
        source: 'NumVerify',
      });
      if (p.lineType) {
        const isVoip = p.lineType.toLowerCase().includes('voip');
        out.indicators.push({
          id: 'line-type',
          name: 'Line type',
          status: isVoip ? 'warning' : 'pass',
          description: `${p.lineType.charAt(0).toUpperCase()}${p.lineType.slice(1)}${p.carrier ? ` (${p.carrier})` : ''}.${isVoip ? ' VoIP numbers are common in phone scams.' : ''}`,
          severity: isVoip ? 'high' : 'low',
          source: 'NumVerify',
        });
      }
      out.details.numverify = {
        title: 'NumVerify',
        data: { valid: p.valid, country: p.countryName || 'unknown', carrier: p.carrier || 'unknown', 'line type': p.lineType || 'unknown', format: p.internationalFormat || 'n/a' },
        status: p.valid ? 'pass' : 'fail',
      };
    },
  });

  runner.add<IPQSPhoneResult>({
    id: 'ipqs',
    label: 'Fraud score',
    source: 'IPQualityScore',
    service: 'ipqs',
    run: ({ key }) => checkIPQSPhone(phone, key!),
    build: (q, out) => {
      if (q.spammer) {
        out.indicators.push({
          id: 'known-spammer',
          name: 'Known spammer',
          status: 'fail',
          description: 'Reported for spam or scam calls.',
          severity: 'critical',
          source: 'IPQualityScore',
        });
      }
      if (q.voip) {
        out.indicators.push({
          id: 'voip-detection',
          name: 'VoIP number',
          status: 'warning',
          description: 'VoIP numbers are common in phone scams.',
          severity: 'high',
          source: 'IPQualityScore',
        });
      }
      out.indicators.push({
        id: 'fraud-score',
        name: 'Fraud score',
        status: q.fraudScore >= 75 ? 'fail' : q.fraudScore >= 50 ? 'warning' : 'pass',
        description: `${q.fraudScore} / 100.${q.recentAbuse ? ' Recently seen in abuse reports.' : ''}`,
        severity: q.fraudScore >= 75 ? 'critical' : q.fraudScore >= 50 ? 'medium' : 'low',
        source: 'IPQualityScore',
      });
      out.details.ipqs = {
        title: 'IPQualityScore',
        data: {
          'fraud score': q.fraudScore,
          valid: q.valid,
          spammer: q.spammer,
          voip: q.voip,
          prepaid: q.prepaid,
          carrier: q.carrier || 'unknown',
          'line type': q.lineType || 'unknown',
        },
        status: q.fraudScore >= 75 ? 'fail' : q.fraudScore >= 50 ? 'warning' : 'pass',
      };
    },
  });

  runner.add<PhoneSpamResult>({
    id: 'rules',
    label: 'Number patterns',
    source: 'Rules',
    sources: 0,
    run: () => checkPhoneSpamDatabases(phone),
    build: (spam, out) => {
      if (spam.isSpam) {
        out.indicators.push({
          id: 'spam-database',
          name: 'Spam patterns',
          status: 'fail',
          description: `${spam.categories.slice(0, 2).join('; ')}.`,
          severity: 'high',
          source: 'Pattern rules',
        });
      } else if (spam.categories.length > 0) {
        out.indicators.push({
          id: 'premium-rate',
          name: 'Number patterns',
          status: 'warning',
          description: `${spam.categories[0]}.`,
          severity: 'medium',
          source: 'Pattern rules',
        });
      }
    },
  });

  await runner.run(phone, 'phone');
  const { indicators, details } = runner.collect();
  return withFacts(buildResult('phone', phone, indicators, details, ctx), {
    abuseScore: null,
    vtDetections: null,
    proxyType: null,
    country: runner.value<PhoneResult>('numverify')?.countryCode || null,
  });
}
