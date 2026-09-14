import { motion } from "framer-motion";
import { Reveal, Stagger, StaggerItem } from "./Reveal";
import { ALGORITHMS, REPO } from "../lib/content";
import { ArrowRight, BookOpen } from "lucide-react";

const EASE = [0.16, 1, 0.3, 1] as const;

export function Algorithm() {
  return (
    <section
      id="algorithm"
      className="relative py-24 md:py-36 scroll-mt-20 border-t border-white/[0.05]"
    >
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-b from-transparent via-accent-500/[0.025] to-transparent" />
      <div className="container-x relative">
        <Reveal>
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-10">
            <div className="lg:col-span-5">
              <div className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 text-[11.5px] uppercase tracking-[0.18em] text-white/60">
                <span className="h-1.5 w-1.5 rounded-full bg-accent-500" />
                Algorithm
              </div>
              <h2 className="mt-5 font-display text-display-lg tracking-tighter text-balance">
                One signature.{" "}
                <span className="text-white/55">Three algorithms.</span>{" "}
                Automatic dispatch.
              </h2>
              <p className="mt-5 text-[16.5px] leading-[1.6] text-white/60 max-w-[440px]">
                From the standard ECDSA equation we derive a linear relation
                and turn key recovery into a bounded search. The engine picks
                the algorithm whose complexity curve fits the range — and falls
                back gracefully when memory becomes the bottleneck.
              </p>

              <div className="mt-8 rounded-2xl border border-white/[0.06] bg-white/[0.02] p-5">
                <div className="font-mono text-[12.5px] leading-[1.7] text-white/65">
                  <div className="text-white/40">// ECDSA, rearranged</div>
                  <div>
                    <span className="text-white/85">d</span> = α · k{" "}
                    <span className="text-accent-400">−</span> β{" "}
                    <span className="text-white/45">(mod n)</span>
                  </div>
                  <div className="mt-1 text-white/45">
                    where α = r⁻¹·s, β = r⁻¹·z
                  </div>
                  <div className="mt-3 text-white/40">
                    // Search for k such that
                  </div>
                  <div>
                    <span className="text-accent-400">k</span> · (α · G) = Q
                    {" "}<span className="text-accent-400">+</span> β · G
                  </div>
                </div>
              </div>

              <a
                href={`${REPO.url}/blob/master/docs/affine-relation-derivation.md`}
                target="_blank"
                rel="noreferrer"
                className="mt-6 inline-flex items-center gap-2 text-[13.5px] text-white/65 hover:text-white transition-colors"
              >
                <BookOpen size={14} />
                <span>Read the full derivation</span>
                <ArrowRight size={14} />
              </a>
            </div>

            <div className="lg:col-span-7">
              <Stagger className="space-y-3">
                {ALGORITHMS.map((a, i) => (
                  <StaggerItem key={a.label} index={i}>
                    <article className="relative group rounded-2xl border border-white/[0.07] bg-gradient-to-r from-white/[0.03] to-transparent p-5 md:p-6 transition-all hover:border-white/[0.16]">
                      <div className="absolute inset-y-3 left-0 w-[2px] rounded-full bg-gradient-to-b from-accent-500 to-accent-700/0 opacity-60" />
                      <div className="flex flex-col md:flex-row md:items-center gap-5">
                        <div className="shrink-0 w-[150px]">
                          <div className="font-mono text-[12px] tracking-tight text-accent-400">
                            {a.range}
                          </div>
                          <div className="mt-1 text-[15.5px] font-semibold tracking-tight text-white">
                            {a.label}
                          </div>
                        </div>
                        <div className="hidden md:block w-px h-10 bg-white/10" />
                        <div className="flex-1">
                          <p className="text-[14px] leading-[1.55] text-white/65 max-w-[440px]">
                            {a.summary}
                          </p>
                          <div className="mt-2 inline-flex items-center gap-2 rounded-md bg-white/[0.04] border border-white/[0.06] px-2.5 py-1 font-mono text-[11.5px] text-white/55">
                            {a.complexity}
                          </div>
                        </div>
                        <div className="hidden md:flex shrink-0 flex-col items-end gap-2 text-right">
                          <span className="font-mono text-[10.5px] uppercase tracking-[0.18em] text-white/40">
                            Tier {i + 1}
                          </span>
                          {a.fallback && (
                            <span className="text-[10px] uppercase tracking-[0.16em] text-accent-400/90">
                              Auto-fallback
                            </span>
                          )}
                        </div>
                      </div>
                    </article>
                  </StaggerItem>
                ))}
              </Stagger>

              {/* Dispatch indicator */}
              <Reveal delay={0.1}>
                <div className="mt-6 relative h-[60px] rounded-2xl border border-white/[0.06] bg-white/[0.015] overflow-hidden">
                  <div className="absolute inset-0 flex items-center">
                    <motion.div
                      className="h-full w-[2px] bg-gradient-to-b from-accent-300 via-accent-500 to-accent-700"
                      initial={{ x: "10%" }}
                      animate={{ x: "95%" }}
                      transition={{
                        duration: 4,
                        repeat: Infinity,
                        ease: "easeInOut",
                      }}
                      style={{ filter: "drop-shadow(0 0 6px rgba(241,130,58,0.6))" }}
                    />
                  </div>
                  <div className="relative h-full grid grid-cols-3 text-[11px] uppercase tracking-[0.16em] text-white/45">
                    <div className="flex items-center justify-center border-r border-white/[0.05]">
                      small
                    </div>
                    <div className="flex items-center justify-center border-r border-white/[0.05]">
                      medium
                    </div>
                    <div className="flex items-center justify-center">large</div>
                  </div>
                </div>
                <p className="mt-2 text-[12px] text-white/40 text-center">
                  log₂ N candidate count — engine selects the optimal tier
                </p>
              </Reveal>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}