'use client';

import { useCallback, useEffect, useState } from 'react';
import { resultCsvValues, toCsv } from '@/lib/csv';
import type { AnalysisResult } from '@/types';

// "Add to CSV" collects rows in this browser only, one per target
const KEY = 'oa-csv-rows';

type Row = (string | number | null)[];

function read(): Row[] {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as Row[]) : [];
  } catch {
    return [];
  }
}

function write(rows: Row[]) {
  try {
    localStorage.setItem(KEY, JSON.stringify(rows));
  } catch {
    // storage unavailable (private mode); the basket just won't persist
  }
}

export function useCsvBasket() {
  const [rows, setRows] = useState<Row[]>([]);
  useEffect(() => setRows(read()), []);

  const add = useCallback((result: AnalysisResult) => {
    const row = resultCsvValues(result);
    const next = [...read().filter((r) => r[0] !== row[0]), row];
    write(next);
    setRows(next);
  }, []);

  const clear = useCallback(() => {
    write([]);
    setRows([]);
  }, []);

  const download = useCallback(() => {
    const blob = new Blob([toCsv(read())], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `osint-checks-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  return { count: rows.length, has: (target: string) => rows.some((r) => r[0] === target), add, clear, download };
}
