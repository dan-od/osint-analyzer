import type { PivotLink } from '@/types';

/** Compact "Open in" buttons, for places without the side panel (bulk row detail) */
export default function PivotLinks({ pivots }: { pivots: PivotLink[] }) {
  if (pivots.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {pivots.map((pivot) => (
        <a key={pivot.label} href={pivot.url} target="_blank" rel="noopener noreferrer" className="oa-btn h-9 px-3 text-[13px]">
          Open in {pivot.label}
        </a>
      ))}
    </div>
  );
}
