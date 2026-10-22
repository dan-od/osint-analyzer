// Turns pasted text or CSV content into a deduplicated list of bulk targets.
// Runs in the browser (live preview) and on the server (authoritative).
//
// CSV (several lines, commas in the first): a column named ip, domain,
// target or url is used; otherwise the first column. Anything else is read
// as a list separated by new lines, commas, semicolons or spaces.
import { validateInput } from './utils';
import { internalIpReason, parseIp } from './ip';
import type { BulkParseResult, BulkTarget } from '@/types/bulk';

/** Most targets any job can take (admins, and accounts an admin has raised) */
export const BULK_MAX_TARGETS = 500;
/** Per-job cap for a new account until an admin raises it */
export const NEW_ACCOUNT_BULK_TARGETS = 50;
const KNOWN_COLUMNS = ['ip', 'domain', 'target', 'url'];

/** Undo common IOC defanging: hxxp://, example[.]com, 1.2.3[.]4, [:] */
export function refang(value: string): string {
  return value
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
    .replace(/\[:\]/g, ':')
    .replace(/^hxxp(s?):\/\//i, 'http$1://')
    .replace(/^\.+|\.+$/g, '');
}

function splitCsvLine(line: string): string[] {
  const cells: string[] = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else cell += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') {
      cells.push(cell);
      cell = '';
    } else cell += ch;
  }
  cells.push(cell);
  return cells.map((c) => c.trim());
}

export interface CsvPick {
  values: string[];
  /** Which column was used */
  column: string | null;
}

/** Picks the target column out of CSV text, or null when the text isn't CSV */
export function pickCsvColumn(text: string): CsvPick | null {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2 || !lines[0].includes(',')) return null;
  const header = splitCsvLine(lines[0]).map((h) => h.toLowerCase().replace(/^﻿/, ''));
  const known = header.findIndex((h) => KNOWN_COLUMNS.includes(h));
  if (known >= 0) {
    return { values: lines.slice(1).map((l) => splitCsvLine(l)[known] ?? ''), column: header[known] };
  }
  return { values: lines.map((l) => splitCsvLine(l)[0] ?? ''), column: null };
}

export function parseBulkInput(
  text: string,
  maxTargets: number = BULK_MAX_TARGETS
): BulkParseResult & { candidates: number; column: string | null; csv: boolean } {
  const csv = pickCsvColumn(text);
  const raw = csv ? csv.values : text.split(/[\s,;"'|<>]+/);
  const tokens = raw.map((t) => refang(t.trim())).filter(Boolean);

  const seen = new Set<string>();
  const targets: BulkTarget[] = [];
  const result: Omit<BulkParseResult, 'targets'> = {
    duplicates: 0,
    internal: [],
    unsupported: [],
    invalid: [],
    truncated: 0,
  };

  for (const token of tokens) {
    const validation = validateInput(token);
    if (!validation.isValid || !validation.type) {
      result.invalid.push(token);
      continue;
    }
    if (validation.type !== 'ip' && validation.type !== 'domain') {
      result.unsupported.push(token);
      continue;
    }
    const target = validation.normalizedInput;
    const key = `${validation.type}:${target}`;
    if (seen.has(key)) {
      result.duplicates++;
      continue;
    }
    seen.add(key);
    if (validation.type === 'ip' && internalIpReason(parseIp(target)!)) {
      result.internal.push(target);
      continue;
    }
    if (targets.length >= maxTargets) {
      result.truncated++;
      continue;
    }
    targets.push({ target, type: validation.type });
  }

  return { targets, ...result, candidates: tokens.length, column: csv?.column ?? null, csv: !!csv };
}
