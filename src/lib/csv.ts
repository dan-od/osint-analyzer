// One CSV format for bulk exports and the results page's "Add to CSV"
import type { AnalysisResult } from '@/types';

export const CSV_HEADER = [
  'target',
  'verdict',
  'risk score',
  'abuse score',
  'VT detections',
  'blocklist hits',
  'proxy type',
  'country',
  'top finding',
];

export function csvCell(value: string | number | null | undefined): string {
  let text = value === null || value === undefined ? '' : String(value);
  // Stop spreadsheet apps from treating values as formulas (CSV injection)
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function csvRow(values: (string | number | null | undefined)[]): string {
  return values.map(csvCell).join(',');
}

export function resultCsvValues(result: AnalysisResult): (string | number | null)[] {
  const f = result.facts;
  return [
    result.query,
    f?.verdict ?? result.riskLevel,
    result.riskScore,
    f?.abuseScore ?? null,
    f?.vtDetections ?? null,
    f?.blocklistHits ?? null,
    f?.proxyType ?? null,
    f?.country ?? null,
    f?.topFinding ?? null,
  ];
}

export function toCsv(rows: (string | number | null | undefined)[][]): string {
  return [CSV_HEADER.join(','), ...rows.map(csvRow)].join('\r\n') + '\r\n';
}
