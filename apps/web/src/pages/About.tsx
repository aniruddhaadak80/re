import { ExternalLink, Globe, Heart } from 'lucide-react';
import { PageHeader } from '../components/ui';
import { SOCIALS, REPO } from '../components/Layout';
import { GithubIcon } from '../components/icons';
import { useRouteSeo } from '../lib/seo';

export default function About() {
  useRouteSeo('/about');
  const base = import.meta.env.BASE_URL;
  return (
    <div>
      <PageHeader eyebrow="About" title="Who builds RevLens" />
      <div className="container-x grid grid-cols-1 gap-8 lg:grid-cols-[320px_minmax(0,1fr)]">
        <div className="card h-fit p-6 text-center">
          <img src={`${base}author/aniruddha-adak.webp`} alt="Portrait of Aniruddha Adak" width={160} height={160} className="mx-auto h-40 w-40 rounded-full border-2 border-accent/60 object-cover shadow-glow"
            onError={(e) => { e.currentTarget.style.display = 'none'; }} />
          <h2 className="mt-5 whitespace-nowrap text-xl font-semibold">Aniruddha Adak</h2>
          <p className="text-sm text-muted">AI Agent Engineer and full-stack developer</p>
          <p className="text-sm text-muted">Kolkata, India</p>
          <div className="mt-5 flex justify-center gap-2">
            {SOCIALS.map(({ href, label, Icon }) => <a key={label} href={href} target="_blank" rel="noreferrer" aria-label={label} className="grid grid-cols-1 h-10 w-10 place-items-center rounded-xl border border-line text-muted transition hover:-translate-y-0.5 hover:border-accent/60 hover:text-ink"><Icon size={16} /></a>)}
          </div>
          <a href="https://aniruddha-agency.vercel.app/" target="_blank" rel="noreferrer" className="btn-ghost mt-4 w-full"><Globe size={15} />Portfolio</a>
        </div>
        <div className="max-w-3xl space-y-5 text-[15.5px] leading-7">
          <p>Aniruddha Adak is an AI agent engineer and full-stack developer from Kolkata. He is studying for a B.Tech in Computer Science and Engineering at Budge Budge Institute of Technology, class of 2022 to 2026.</p>
          <p>Most of his work sits where agents meet real software. He builds agentic harnesses and production-grade agent skills: the small, sharp tools that let a model look at something real and report back with evidence instead of guesses. RevLens came out of that work. Agents kept being asked what was inside a binary or a package, and there was no light tool that could answer without a heavy install.</p>
          <p>He cares about AI safety and about open source. He takes part in Hacktoberfest and community hackathons, writes about what he builds on DEV, and tests new models as they ship. RevLens is MIT licensed and open to contributions.</p>
          <div className="card p-5">
            <p className="font-semibold">Also by Aniruddha</p>
            <p className="mt-1 text-sm text-muted">OpenFile is another open source project of his. Take a look on GitHub.</p>
            <a href="https://github.com/aniruddhaadak80/OpenFile" target="_blank" rel="noreferrer" className="mt-3 inline-flex items-center gap-2 text-sm text-ink hover:underline"><GithubIcon size={15} />aniruddhaadak80/OpenFile<ExternalLink size={13} /></a>
          </div>
          <div className="card p-5" id="credits">
            <p className="flex items-center gap-2 font-semibold"><Heart size={16} className="text-ink" />Inspiration and credits</p>
            <p className="mt-2 text-sm leading-6 text-muted">RevLens is inspired by <a href="https://github.com/morluto/rea" target="_blank" rel="noreferrer" className="text-ink underline underline-offset-4">morluto/rea</a>, which is MIT licensed and does deep reverse engineering with agents on top of tools like Ghidra and IDA. RevLens is a separate project with its own code. It is not affiliated with REA and is not an official REA release.</p>
            <p className="mt-2 text-sm leading-6 text-muted">The source for RevLens lives at <a href={REPO} target="_blank" rel="noreferrer" className="text-ink underline underline-offset-4">github.com/aniruddhaadak80/re</a>.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
