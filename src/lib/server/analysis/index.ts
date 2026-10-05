// Entry point used by the single-lookup API and the bulk worker
import type { AnalysisResult, ValidationResult } from '@/types';
import type { AnalysisContext } from './context';
import { analyzeEmail } from './email';
import { analyzeDomain } from './domain';
import { analyzePhone } from './phone';
import { analyzeCrypto } from './crypto';
import { analyzeIp } from './ip';

export { createAnalysisContext, type AnalysisContext } from './context';

export async function analyzeTarget(
  validation: ValidationResult & { type: NonNullable<ValidationResult['type']> },
  ctx: AnalysisContext
): Promise<AnalysisResult> {
  const input = validation.normalizedInput;
  switch (validation.type) {
    case 'email':
      return analyzeEmail(input, ctx);
    case 'domain':
      return analyzeDomain(input, ctx);
    case 'phone':
      return analyzePhone(input, ctx);
    case 'crypto':
      return analyzeCrypto(input, ctx);
    case 'ip':
      return analyzeIp(input, ctx);
  }
}
