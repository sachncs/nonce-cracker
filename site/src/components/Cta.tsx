import { ArrowRight, Github, BookOpen } from "lucide-react";
import { Reveal } from "./Reveal";
import { REPO } from "../lib/content";

export function Cta() {
  return (
    <section className="relative py-24 md:py-36 border-t border-white/[0.05]">
      <div className="container-x">
        <Reveal>
          <div className="relative overflow-hidden rounded-[28px] border border-white/[0.07] bg-gradient-to-b from-white/[0.04] to-white/[0.01]">
            {/* Background ornamentation */}
            <div className="pointer-events-none absolute inset-0">
              <div className="absolute -top-32 left-1/2 -translate-x-1/2 h-[480px] w-[680px] bg-gradient-radial opacity-90" />
              <svg
                className="absolute inset-0 w-full h-full opacity-[0.12]"
                viewBox="0 0 1200 400"
                preserveAspectRatio="xMidYMid slice"
                aria-hidden
              >
                <defs>
                  <linearGradient id="ctaLine" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="rgba(241,130,58,0)" />
                    <stop offset="50%" stopColor="rgba(241,130,58,0.6)" />
                    <stop offset="100%" stopColor="rgba(241,130,58,0)" />
                  </linearGradient>
                </defs>
                {Array.from({ length: 24 }).map((_, i) => (
                  <line
                    key={i}
                    x1={0}
                    y1={(i / 24) * 400}
                    x2={1200}
                    y2={(i / 24) * 400}
                    stroke="url(#ctaLine)"
                    strokeWidth="0.5"
                  />
                ))}
              </svg>
            </div>

            <div className="relative px-6 py-16 md:px-16 md:py-24 text-center">
              <div className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.04] px-3 py-1 text-[11.5px] uppercase tracking-[0.18em] text-white/60">
                <span className="h-1.5 w-1.5 rounded-full bg-accent-500" />
                Get started
              </div>
              <h2 className="mt-6 font-display text-display-xl tracking-tightest text-balance max-w-[820px] mx-auto">
                Built for cryptographers
                <br />
                <span className="text-gradient-accent">who need answers, fast.</span>
              </h2>
              <p className="mt-6 mx-auto max-w-[560px] text-[16.5px] leading-[1.6] text-white/65 text-pretty">
                Clone the repo, build with <span className="font-mono text-accent-300">cargo build --release</span>, and recover your first key in under five minutes.
              </p>
              <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
                <a
                  href={REPO.url}
                  target="_blank"
                  rel="noreferrer"
                  className="btn-primary inline-flex items-center gap-2 rounded-full px-6 py-3.5 text-[15px] font-medium transition-all"
                >
                  <Github size={16} />
                  <span>Open the repository</span>
                  <ArrowRight size={16} />
                </a>
                <a
                  href={`${REPO.url}#installation`}
                  className="inline-flex items-center gap-2 rounded-full border border-white/[0.12] bg-white/[0.04] hover:bg-white/[0.07] hover:border-white/[0.2] px-6 py-3.5 text-[15px] font-medium text-white transition-all"
                >
                  <BookOpen size={15} />
                  <span>Installation guide</span>
                </a>
              </div>

              <div className="mt-12 grid grid-cols-3 gap-x-6 max-w-[480px] mx-auto">
                <Mini label="Version" value="0.6.0" />
                <Mini label="License" value="MIT" />
                <Mini label="Channel" value="stable" />
              </div>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function Mini({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-l border-white/[0.08] pl-4 text-left">
      <div className="font-display text-[18px] font-semibold tracking-tight text-white">
        {value}
      </div>
      <div className="mt-1 text-[11px] uppercase tracking-[0.16em] text-white/40">
        {label}
      </div>
    </div>
  );
}