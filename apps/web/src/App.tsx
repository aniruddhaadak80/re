import { Suspense, lazy, useEffect } from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { Layout } from './components/Layout';
import Home from './pages/Home';
import { useReducedMotionSetting } from './lib/settings';

const Analyze = lazy(() => import('./pages/Analyze'));
const Diff = lazy(() => import('./pages/Diff'));
const Verify = lazy(() => import('./pages/Verify'));
const Docs = lazy(() => import('./pages/Docs'));
const Blog = lazy(() => import('./pages/Blog'));
const About = lazy(() => import('./pages/About'));
const Changelog = lazy(() => import('./pages/Changelog'));
const Settings = lazy(() => import('./pages/Settings'));
const NotFound = lazy(() => import('./pages/NotFound'));

function ScrollManager() {
  const { pathname, hash } = useLocation();
  useEffect(() => {
    if (hash) {
      const t = setTimeout(() => document.getElementById(decodeURIComponent(hash.slice(1)))?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 120);
      return () => clearTimeout(t);
    }
    window.scrollTo(0, 0);
    return undefined;
  }, [pathname, hash]);
  return null;
}

const Fallback = () => <div className="container-x py-24"><div className="h-8 w-48 animate-pulse rounded-lg bg-surface2" /><div className="mt-4 h-4 w-80 max-w-full animate-pulse rounded bg-surface2" /></div>;

export default function App() {
  const location = useLocation();
  const reduced = useReducedMotionSetting();
  const section = location.pathname.split('/')[1] ?? '';
  return (
    <Layout>
      <ScrollManager />
      <AnimatePresence mode="wait">
        <motion.div key={section === 'docs' || section === 'blog' ? section : location.pathname}
          initial={reduced ? false : { opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={reduced ? undefined : { opacity: 0, y: -6 }} transition={{ duration: 0.18, ease: 'easeOut' }}>
          <Suspense fallback={<Fallback />}>
            <Routes location={location}>
              <Route path="/" element={<Home />} />
              <Route path="/analyze" element={<Analyze />} />
              <Route path="/diff" element={<Diff />} />
              <Route path="/verify" element={<Verify />} />
              <Route path="/docs" element={<Docs />} />
              <Route path="/docs/:slug" element={<Docs />} />
              <Route path="/blog" element={<Blog />} />
              <Route path="/blog/:slug" element={<Blog />} />
              <Route path="/about" element={<About />} />
              <Route path="/changelog" element={<Changelog />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </motion.div>
      </AnimatePresence>
    </Layout>
  );
}
