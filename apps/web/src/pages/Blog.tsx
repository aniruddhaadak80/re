import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ChevronLeft, ChevronRight, Clock, Newspaper, Square, Volume2 } from 'lucide-react';
import { Markdown } from '../components/Markdown';
import { Empty, PageHeader } from '../components/ui';
import { POSTS, assetUrl, formatDate } from '../lib/content';
import { useRouteSeo, useSeo } from '../lib/seo';
import { Toc } from './Docs';
import NotFound from './NotFound';

function plain(md: string): string {
  return md.replace(/```[\s\S]*?```/g, ' ').replace(/!\[[^\]]*\]\([^)]*\)/g, ' ').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1').replace(/[#>*_`|-]/g, ' ').replace(/\s+/g, ' ').trim();
}

function ReadAloud({ text }: { text: string }) {
  const supported = typeof window !== 'undefined' && 'speechSynthesis' in window;
  const [on, setOn] = useState(false);
  useEffect(() => () => { if (supported) window.speechSynthesis.cancel(); }, [supported]);
  if (!supported) return null;
  return (
    <button type="button" className="btn-ghost btn-sm" aria-pressed={on} data-testid="read-aloud"
      onClick={() => {
        if (on) { window.speechSynthesis.cancel(); setOn(false); return; }
        const u = new SpeechSynthesisUtterance(text);
        u.rate = 1; u.onend = () => setOn(false); u.onerror = () => setOn(false);
        window.speechSynthesis.cancel(); window.speechSynthesis.speak(u); setOn(true);
      }}>
      {on ? <Square size={13} /> : <Volume2 size={14} />}{on ? 'Stop reading' : 'Read aloud'}
    </button>
  );
}

function Cover({ src, alt }: { src?: string; alt: string }) {
  if (!src) return null;
  return <img src={assetUrl(src, 'blog')} alt={alt} loading="lazy" className="aspect-[16/8] w-full rounded-xl border border-line object-cover" onError={(e) => { e.currentTarget.style.display = 'none'; }} />;
}

function Index() {
  useRouteSeo('/blog');
  return (
    <div>
      <PageHeader eyebrow="Blog" title="Notes from the lens">Writing on reverse engineering, supply chain triage and building tools that agents can trust.</PageHeader>
      <div className="container-x">
        {!POSTS.length ? <Empty title="No posts yet" icon={<Newspaper size={28} />}>The first posts are being written.</Empty> : (
          <div className="grid grid-cols-1 gap-5 md:grid-cols-2 lg:grid-cols-3">
            {POSTS.map((p) => (
              <Link key={p.slug} to={`/blog/${p.slug}`} className="card card-hover group flex flex-col overflow-hidden p-4" data-testid="post-card">
                <Cover src={p.cover} alt="" />
                <div className="mt-4 flex items-center gap-3 text-xs text-muted"><span>{formatDate(p.date)}</span><span className="flex items-center gap-1"><Clock size={12} />{p.readingMinutes} min read</span></div>
                <h2 className="mt-2 text-lg font-semibold leading-snug transition group-hover:text-ink">{p.title}</h2>
                <p className="mt-2 flex-1 text-sm leading-6 text-muted">{p.summary}</p>
                {p.tags.length > 0 && <div className="mt-3 flex flex-wrap gap-1.5">{p.tags.map((t) => <span key={t} className="chip">{t}</span>)}</div>}
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function PostView({ slug }: { slug: string }) {
  const i = POSTS.findIndex((p) => p.slug === slug);
  const post = POSTS[i];
  useSeo(post ? `${post.title} | RevLens blog` : 'Post not found | RevLens', post?.summary ?? 'This post does not exist.');
  if (!post) return <NotFound />;
  const newer = POSTS[i - 1], older = POSTS[i + 1];
  const body = post.body.replace(/^#\s+.+\n/, '');
  return (
    <div className="container-x py-10">
      <div className="grid grid-cols-1 gap-8 xl:grid-cols-[minmax(0,1fr)_200px]">
        <article className="mx-auto w-full min-w-0 max-w-3xl">
          <Link to="/blog" className="text-sm text-muted hover:text-ink">Back to the blog</Link>
          <h1 className="mt-4 text-3xl font-semibold leading-tight tracking-tight sm:text-4xl">{post.title}</h1>
          <div className="mt-4 flex flex-wrap items-center gap-3 text-sm text-muted">
            <span>{formatDate(post.date)}</span><span className="flex items-center gap-1"><Clock size={14} />{post.readingMinutes} min read</span>
            <ReadAloud text={`${post.title}. ${plain(body)}`} />
          </div>
          {post.tags.length > 0 && <div className="mt-3 flex flex-wrap gap-1.5">{post.tags.map((t) => <span key={t} className="chip">{t}</span>)}</div>}
          <div className="mt-6"><Cover src={post.cover} alt="" /></div>
          <div className="mt-8"><Markdown source={body} from="blog" /></div>
          <div className="mt-12 grid grid-cols-1 gap-3 border-t border-line pt-6 sm:grid-cols-2">
            {older ? <Link to={`/blog/${older.slug}`} className="card card-hover flex items-center gap-2 p-4 text-sm"><ChevronLeft size={16} className="shrink-0 text-ink" /><span><span className="block text-xs text-muted">Older</span>{older.title}</span></Link> : <span />}
            {newer && <Link to={`/blog/${newer.slug}`} className="card card-hover flex items-center justify-end gap-2 p-4 text-right text-sm"><span><span className="block text-xs text-muted">Newer</span>{newer.title}</span><ChevronRight size={16} className="shrink-0 text-ink" /></Link>}
          </div>
        </article>
        <Toc headings={post.headings} />
      </div>
    </div>
  );
}

export default function Blog() {
  const { slug } = useParams();
  return slug ? <PostView slug={slug} /> : <Index />;
}
