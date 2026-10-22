// Plain document layout for /privacy and /terms: one column at a readable
// measure, a heading per section, nothing decorative.
import type { ReactNode } from 'react';
import PageChrome from '@/components/chrome/PageChrome';
import { ALT_CONTACT_EMAIL, CONTACT_EMAIL, formatLegalDate, LEGAL_LAST_UPDATED } from '@/lib/legal';

export function LegalDoc({ title, intro, children }: { title: string; intro: ReactNode; children: ReactNode }) {
  return (
    <PageChrome>
      <article className="oa-wrap pb-16 pt-10">
        <div className="flex max-w-[70ch] flex-col gap-4 text-[16px] leading-[1.6] text-ink-body">
          <header className="flex flex-col gap-2 border-b border-line pb-6">
            <h1 className="oa-display text-[34px] leading-[1.1]">{title}</h1>
            <p className="m-0 text-[14px] text-muted">
              Last updated <time dateTime={LEGAL_LAST_UPDATED}>{formatLegalDate(LEGAL_LAST_UPDATED)}</time>
            </p>
            <div className="m-0 text-ink-body">{intro}</div>
          </header>
          {children}
        </div>
      </article>
    </PageChrome>
  );
}

export function LegalSection({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-h`} className="flex scroll-mt-6 flex-col gap-3 pt-6">
      <h2 id={`${id}-h`} className="m-0 text-[21px] font-semibold text-ink-strong">
        {title}
      </h2>
      {children}
    </section>
  );
}

export const P = ({ children }: { children: ReactNode }) => <p className="m-0">{children}</p>;

export const List = ({ children }: { children: ReactNode }) => (
  <ul className="m-0 flex list-disc flex-col gap-2 pl-[22px] marker:text-muted">{children}</ul>
);

/** A small two- or three-column table with a visible caption */
export function LegalTable({ caption, head, rows }: { caption: string; head: string[]; rows: ReactNode[][] }) {
  return (
    <div className="oa-tablewrap" tabIndex={0} role="region" aria-label={caption}>
      <table className="oa-table oa-legal">
        <caption className="border-b border-line bg-panel px-[14px] py-[10px] text-left text-[14px] font-medium text-ink">{caption}</caption>
        <thead>
          <tr>
            {head.map((h) => (
              <th key={h} scope="col">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {row.map((cell, j) =>
                j === 0 ? (
                  <th key={j} scope="row" className="!border-b !border-line align-top font-mono text-[13px] font-normal text-ink">
                    {cell}
                  </th>
                ) : (
                  <td key={j} data-label={head[j]} className="text-ink-body">
                    {cell}
                  </td>
                )
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** "a@… (or b@…)": the primary contact first, the alternate after it */
export function Contact() {
  return (
    <>
      <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a> (or <a href={`mailto:${ALT_CONTACT_EMAIL}`}>{ALT_CONTACT_EMAIL}</a>)
    </>
  );
}
