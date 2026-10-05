'use client';

import { useEffect, useState } from 'react';

export interface DocsNavItem {
  id: string;
  label: string;
  sub?: boolean;
}

/** Sticky section list that highlights the section being read */
export default function DocsNav({ items }: { items: DocsNavItem[] }) {
  const [active, setActive] = useState(items[0]?.id);

  useEffect(() => {
    const sections = items
      .filter((i) => !i.sub)
      .map((i) => document.getElementById(i.id))
      .filter((el): el is HTMLElement => !!el);
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.id);
      },
      { rootMargin: '-10% 0px -70% 0px' }
    );
    sections.forEach((s) => observer.observe(s));
    return () => observer.disconnect();
  }, [items]);

  return (
    <nav aria-label="Docs sections" className="flex max-w-[240px] min-[721px]:sticky min-[721px]:top-5 flex-[1_1_200px] flex-col gap-[2px] self-start text-[14px]">
      {items.map((item) =>
        item.sub ? (
          <a key={item.id} href={`#${item.id}`} className="py-[6px] pl-6 pr-3 text-[13px] text-faint no-underline hover:text-ink">
            {item.label}
          </a>
        ) : (
          <a
            key={item.id}
            href={`#${item.id}`}
            aria-current={active === item.id ? 'true' : undefined}
            className={`rounded border-l-2 px-3 py-2 no-underline ${
              active === item.id ? 'border-l-accent bg-raised text-ink hover:text-ink' : 'border-l-transparent text-muted hover:text-ink'
            }`}
          >
            {item.label}
          </a>
        )
      )}
    </nav>
  );
}
