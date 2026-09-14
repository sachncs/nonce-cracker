import {
  Key,
  Layers,
  Atom,
  Table2,
  ShieldCheck,
  Terminal,
  type LucideIcon,
} from "lucide-react";
import { Reveal, Stagger, StaggerItem } from "./Reveal";
import { FEATURES } from "../lib/content";

const ICONS: Record<string, LucideIcon> = {
  key: Key,
  ladder: Layers,
  atom: Atom,
  table: Table2,
  shield: ShieldCheck,
  terminal: Terminal,
};

export function Features() {
  return (
    <section
      id="features"
      className="relative py-24 md:py-36 scroll-mt-20"
    >
      <div className="container-x">
        <Reveal>
          <div className="max-w-2xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 text-[11.5px] uppercase tracking-[0.18em] text-white/60">
              <span className="h-1.5 w-1.5 rounded-full bg-accent-500" />
              Features
            </div>
            <h2 className="mt-5 font-display text-display-lg tracking-tighter text-balance">
              Everything required to recover a key,{" "}
              <span className="text-white/55">nothing you don't.</span>
            </h2>
            <p className="mt-5 text-[16.5px] leading-[1.6] text-white/60 max-w-[560px]">
              A focused tool for a narrow job. The CLI parses, validates, and
              dispatches. The math is honest, the algorithm picks itself, and
              the run completes — or exits cleanly with a structured error.
            </p>
          </div>
        </Reveal>

        <Stagger className="mt-14 md:mt-20 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {FEATURES.map((f, i) => {
            const Icon = ICONS[f.icon] ?? Atom;
            return (
              <StaggerItem key={f.title} index={i}>
                <article className="group relative h-full rounded-2xl border border-white/[0.06] bg-gradient-to-b from-white/[0.025] to-white/[0.01] p-6 transition-all duration-300 hover:border-white/[0.14] hover:from-white/[0.05] hover:to-white/[0.015]">
                  <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                  <div className="flex items-start gap-4">
                    <div className="relative shrink-0">
                      <div className="absolute -inset-1 bg-accent-500/20 blur-md rounded-lg opacity-0 group-hover:opacity-100 transition-opacity" />
                      <div className="relative h-10 w-10 rounded-lg border border-white/[0.08] bg-white/[0.04] grid place-items-center">
                        <Icon size={18} className="text-accent-400" />
                      </div>
                    </div>
                    <div>
                      <h3 className="text-[16px] font-semibold tracking-tight text-white">
                        {f.title}
                      </h3>
                      <p className="mt-2.5 text-[14.5px] leading-[1.55] text-white/60">
                        {f.body}
                      </p>
                    </div>
                  </div>
                </article>
              </StaggerItem>
            );
          })}
        </Stagger>
      </div>
    </section>
  );
}