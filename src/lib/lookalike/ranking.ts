// Tranco list files: "rank,domain" per line, rank 1 first.
import type { RankedDomain } from './detect';

export function parseRanking(text: string): RankedDomain[] {
  const out: RankedDomain[] = [];
  for (const line of text.split('\n')) {
    const comma = line.indexOf(',');
    if (comma < 1) continue;
    const rank = Number(line.slice(0, comma));
    const domain = line.slice(comma + 1).trim().toLowerCase();
    if (Number.isInteger(rank) && rank > 0 && domain) out.push({ rank, domain });
  }
  return out;
}
