// Verdict language: red, amber, green are only used for Fail / Warn / Pass,
// and always as a dot plus a word.
import type { AnalysisType, Indicator, RiskLevel } from '@/types';

export type Tone = 'fail' | 'warn' | 'pass' | 'skip';

export function toneForLevel(level: RiskLevel): Tone {
  return level === 'critical' || level === 'high' ? 'fail' : level === 'medium' ? 'warn' : 'pass';
}

export function levelWord(level: RiskLevel): string {
  return { low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' }[level];
}

export function toneForStatus(status: Indicator['status']): Tone {
  return status === 'fail' ? 'fail' : status === 'warning' ? 'warn' : status === 'pass' ? 'pass' : 'skip';
}

export function statusWord(status: Indicator['status']): string {
  return { fail: 'Fail', warning: 'Warn', pass: 'Pass', unknown: 'Skipped' }[status];
}

export const TYPE_LABEL: Record<AnalysisType, string> = {
  email: 'Email address',
  domain: 'Domain',
  ip: 'IP address',
  phone: 'Phone number',
  crypto: 'Crypto wallet',
};

export const TYPE_SHORT: Record<AnalysisType, string> = {
  email: 'email',
  domain: 'domain',
  ip: 'IP',
  phone: 'phone',
  crypto: 'wallet',
};

/** Text colour for a verdict word or score */
export const TONE_INK: Record<Tone, string> = {
  fail: 'text-fail-ink',
  warn: 'text-warn',
  pass: 'text-pass-ink',
  skip: 'text-skip',
};
