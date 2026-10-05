import Link from 'next/link';
import type { CSSProperties } from 'react';

interface SweepMarkProps {
  size?: number;
  stroke?: string;
  dot?: string;
  strokeWidth?: number;
  className?: string;
  style?: CSSProperties;
}

/** The sweep: a scan closing in on the target (Styles.dc.html) */
export function SweepMark({ size = 22, stroke = '#E6E9EC', dot = '#F28C28', strokeWidth = 2, className, style }: SweepMarkProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true" className={className} style={style}>
      <path d="M12 3a9 9 0 0 1 9 9" stroke={stroke} strokeWidth={strokeWidth} strokeLinecap="square" />
      <path d="M12 7.5a4.5 4.5 0 0 1 4.5 4.5" stroke={stroke} strokeWidth={strokeWidth} strokeLinecap="square" />
      <path d="M3 12a9 9 0 0 0 9 9" stroke={stroke} strokeWidth={strokeWidth} strokeOpacity={0.35} strokeLinecap="square" />
      <circle cx="12" cy="12" r="2.4" fill={dot} />
    </svg>
  );
}

/** Five sources converging on the target. Only ever shown animated, while a check runs. */
export function ConvergeMark({ size = 52 }: { size?: number }) {
  const points: [number, number, string][] = [
    [5, 6, '0s'],
    [19, 6, '.3s'],
    [4, 15, '.6s'],
    [20, 15, '.9s'],
    [12, 20, '1.2s'],
  ];
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ flex: '0 0 auto' }}>
      <path d="M12 12 5 6M12 12l7-6M12 12 4 15M12 12l8 3M12 12v8" stroke="#3A4149" strokeWidth="1" />
      {points.map(([cx, cy, delay]) => (
        <circle key={`${cx}-${cy}`} cx={cx} cy={cy} r="1.7" fill="#E6E9EC" style={{ animation: `oa-pulse 1.5s ${delay} infinite` }} />
      ))}
      <circle cx="12" cy="12" r="3" fill="#F28C28" />
    </svg>
  );
}

export function LogoLink({ href = '/' }: { href?: string }) {
  return (
    <Link
      href={href}
      className="flex items-center gap-[10px] no-underline font-semibold text-[15px] tracking-[0.01em] text-ink hover:text-ink"
    >
      <SweepMark size={22} />
      <span>OSINT Analyzer</span>
    </Link>
  );
}
