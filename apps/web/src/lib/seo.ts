import { useEffect } from 'react';
import routes from '../routes.json';

const SITE = 'https://aniruddhaadak80.github.io';
type Meta = { title: string; description: string };
export const ROUTE_META = routes as Record<string, Meta>;

function setMeta(sel: string, attr: string, value: string) {
  let el = document.head.querySelector(sel);
  if (!el) {
    el = document.createElement(sel.startsWith('link') ? 'link' : 'meta');
    const m = /\[(\w+(?::\w+)?)="([^"]+)"\]/.exec(sel);
    if (m) el.setAttribute(m[1] as string, m[2] as string);
    document.head.appendChild(el);
  }
  el.setAttribute(attr, value);
}

/** Sets title, description, canonical and OG tags for the current page. */
export function useSeo(title: string, description: string, path?: string): void {
  useEffect(() => {
    document.title = title;
    setMeta('meta[name="description"]', 'content', description);
    setMeta('meta[property="og:title"]', 'content', title);
    setMeta('meta[property="og:description"]', 'content', description);
    setMeta('meta[name="twitter:title"]', 'content', title);
    setMeta('meta[name="twitter:description"]', 'content', description);
    const p = path ?? window.location.pathname;
    setMeta('meta[property="og:url"]', 'content', SITE + p);
    setMeta('link[rel="canonical"]', 'href', SITE + p);
  }, [title, description, path]);
}

export function useRouteSeo(route: string): void {
  const m = ROUTE_META[route] ?? { title: 'RevLens', description: ROUTE_META['/']!.description };
  useSeo(m.title, m.description);
}
