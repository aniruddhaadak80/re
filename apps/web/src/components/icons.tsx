import type { SVGProps } from 'react';

type P = SVGProps<SVGSVGElement> & { size?: number };
const base = ({ size = 18, ...p }: P) => ({ width: size, height: size, viewBox: '0 0 24 24', fill: 'currentColor', 'aria-hidden': true, ...p });

export const GithubIcon = (p: P) => (
  <svg {...base(p)}><path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.37-3.88-1.37-.53-1.33-1.28-1.69-1.28-1.69-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.71 1.26 3.37.96.1-.75.4-1.26.73-1.55-2.56-.29-5.25-1.28-5.25-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.42-2.7 5.39-5.27 5.68.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z" /></svg>
);
export const LinkedinIcon = (p: P) => (
  <svg {...base(p)}><path d="M20.45 20.45h-3.56v-5.57c0-1.33-.02-3.04-1.85-3.04-1.86 0-2.14 1.45-2.14 2.94v5.67H9.35V9h3.41v1.56h.05c.48-.9 1.64-1.85 3.37-1.85 3.6 0 4.27 2.37 4.27 5.46v6.28ZM5.34 7.43a2.06 2.06 0 1 1 0-4.13 2.06 2.06 0 0 1 0 4.13ZM7.12 20.45H3.56V9h3.56v11.45ZM22.22 0H1.77C.79 0 0 .77 0 1.73v20.54C0 23.23.79 24 1.77 24h20.45c.98 0 1.78-.77 1.78-1.73V1.73C24 .77 23.2 0 22.22 0Z" /></svg>
);
export const XIcon = (p: P) => (
  <svg {...base(p)}><path d="M18.9 1.15h3.68l-8.04 9.19L24 22.85h-7.4l-5.8-7.58-6.63 7.58H.49l8.6-9.83L0 1.15h7.59l5.24 6.93 6.07-6.93Zm-1.29 19.5h2.04L6.48 3.24H4.3l13.31 17.41Z" /></svg>
);
export const DevIcon = (p: P) => (
  <svg {...base(p)}><path d="M7.42 10.05c-.18-.16-.46-.23-.84-.23H6v4.36h.58c.38 0 .66-.08.84-.23.2-.16.3-.42.3-.79v-2.33c0-.37-.1-.63-.3-.78ZM0 4.94v14.12h24V4.94H0Zm8.56 8.6c0 .78-.24 1.36-.73 1.75-.49.39-1.12.58-1.9.58H4.43V8.13h1.5c.78 0 1.41.19 1.9.58.49.39.73.97.73 1.75v3.08Zm4.5-3.94H10.6v1.66h1.5v1.47h-1.5v1.65h2.46v1.48h-2.94c-.4 0-.74-.34-.74-.74V8.87c0-.4.34-.74.74-.74h2.94v1.47Zm4.97 5.45c-.66 1.53-1.83 1.23-2.35 0l-1.91-7.07h1.62l1.47 5.6 1.47-5.6h1.62l-1.92 7.07Z" /></svg>
);
export const NpmIcon = (p: P) => (
  <svg {...base(p)}><path d="M0 7.33v8h6.67v1.34H12v-1.34h12v-8H0Zm6.67 6.67H5.33v-4H4v4H1.33V8.67h5.34V14Zm4 0v1.33H8V8.67h5.33V14h-2.66Zm12 0h-1.34v-4H20v4h-1.33v-4h-1.34v4h-2.66V8.67h8V14ZM10.67 10H12v2.67h-1.33V10Z" /></svg>
);

/** The RevLens mark: a gold lens with a teal core. */
export const LensMark = ({ size = 28, className = '' }: { size?: number; className?: string }) => (
  <svg width={size} height={size} viewBox="0 0 64 64" className={className} aria-hidden>
    <circle cx="30" cy="30" r="19" fill="none" stroke="rgb(var(--accent))" strokeWidth="5" />
    <circle cx="30" cy="30" r="10" fill="none" stroke="rgb(var(--accent2))" strokeWidth="2" strokeDasharray="4 3" />
    <circle cx="30" cy="30" r="4" fill="#14B8A6" />
    <path d="M44 44 L56 56" stroke="rgb(var(--accent))" strokeWidth="6" strokeLinecap="round" />
  </svg>
);
