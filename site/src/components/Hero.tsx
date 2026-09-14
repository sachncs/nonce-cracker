import { motion } from "framer-motion";
import { ArrowRight, Github, Terminal, Sparkles } from "lucide-react";
import { CurveViz } from "./CurveViz";
import { REPO } from "../lib/content";

const EASE = [0.16, 1, 0.3, 1] as const;

export function Hero() {
  return (
    <section
      id="top"
      className="relative pt-[140px] pb-24 md:pt-[180px] md:pb-32 overflow-hidden"
    >
      {/* Background grid + ambient glow */}
      <div className="absolute inset-0 bg-grid opacity-[0.35] [mask-image:radial-gradient(ellipse_at_50%_30%,#000_30%,transparent_75%)]" />
      <div className="pointer-events-none absolute -top-40 left-1/2 -translate-x-1/2 h-[520px] w-[820px] bg-gradient-radial opacity-90" />
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />

      <div className="container-x relative">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-12 items-center">
          <div className="lg:col-span-7 max-w-[720px]">
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, ease: EASE }}
              className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-[12px] text-white/75 backdrop-blur"
            >
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent-500 opacity-70" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-accent-500" />
              </span>
              <span className="text-white/85">v0.6.0 · secp256k1 · single-signature attack</span>
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 18 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, ease: EASE, delay: 0.05 }}
              className="mt-6 font-display font-semibold tracking-tightest text-balance text-[44px] leading-[0.95] sm:text-[56px] md:text-[68px] lg:text-[76px]"
            >
              Recover an{" "}
              <span className="text-gradient-accent">ECDSA private key</span>{" "}
              from a single signature.
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, ease: EASE, delay: 0.12 }}
              className="mt-6 max-w-[600px] text-[17px] md:text-[18.5px] leading-[1.55] text-white/65 text-pretty"
            >
              <span className="text-white/85 font-medium">nonce-cracker</span>{" "}
              is a high-performance, parallel secp256k1 key-recovery tool built
              in Rust. Three-tier algorithm dispatch turns a single signature
              into a search problem — and solves it on every core you give it.
            </motion.p>

            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, ease: EASE, delay: 0.18 }}
              className="mt-9 flex flex-wrap items-center gap-3"
            >
              <a
                href={REPO.url}
                target="_blank"
                rel="noreferrer"
                className="btn-primary inline-flex items-center gap-2 rounded-full px-5 py-3 text-[14.5px] font-medium transition-all"
              >
                <Github size={15} />
                <span>View on GitHub</span>
                <ArrowRight size={15} />
              </a>
              <a
                href="#cli"
                className="inline-flex items-center gap-2 rounded-full border border-white/[0.1] bg-white/[0.03] hover:bg-white/[0.06] hover:border-white/[0.18] px-5 py-3 text-[14.5px] font-medium text-white transition-all"
              >
                <Terminal size={15} />
                <span>See the CLI</span>
              </a>
            </motion.div>

            <motion.dl
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.8, delay: 0.35 }}
              className="mt-12 grid grid-cols-3 gap-x-6 gap-y-4 max-w-[560px]"
            >
              {[
                { k: "14 ms", v: "Parallel scan", r: "N ≤ 2³²" },
                { k: "3.1 s", v: "Parallel BSGS", r: "N ≤ 2⁵²" },
                { k: "O(√N)", v: "Pollard kangaroo", r: "N > 2⁵²" },
              ].map((s) => (
                <div key={s.v} className="border-l border-white/[0.08] pl-4">
                  <dt className="font-display text-[22px] md:text-[26px] font-semibold tracking-tight">
                    {s.k}
                  </dt>
                  <dd className="mt-1 text-[11px] uppercase tracking-[0.12em] text-white/45 leading-tight">
                    {s.v}
                    <span className="block text-white/30 mt-0.5">{s.r}</span>
                  </dd>
                </div>
              ))}
            </motion.dl>
          </div>

          <motion.div
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 1.1, ease: EASE, delay: 0.15 }}
            className="lg:col-span-5 relative"
          >
            <div className="relative aspect-[6/4.2] w-full">
              <div className="absolute inset-0 rounded-3xl border border-white/[0.07] bg-gradient-to-b from-white/[0.04] to-white/[0.01] overflow-hidden">
                <div className="absolute inset-0">
                  <CurveViz />
                </div>

                {/* Floating tags */}
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.7, duration: 0.6 }}
                  className="absolute top-4 left-4 inline-flex items-center gap-1.5 rounded-full bg-black/40 backdrop-blur border border-white/[0.08] px-2.5 py-1 text-[10.5px] uppercase tracking-[0.16em] text-white/70"
                >
                  <Sparkles size={11} className="text-accent-400" />
                  <span>secp256k1</span>
                </motion.div>
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.85, duration: 0.6 }}
                  className="absolute top-4 right-4 rounded-md bg-black/40 backdrop-blur border border-white/[0.08] px-2.5 py-1 text-[10.5px] font-mono text-white/65"
                >
                  y² = x³ + 7
                </motion.div>
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 1.0, duration: 0.6 }}
                  className="absolute bottom-4 left-4 rounded-md bg-black/40 backdrop-blur border border-white/[0.08] px-2.5 py-1 text-[10.5px] font-mono text-accent-400"
                >
                  d = α·k − β (mod n)
                </motion.div>
              </div>

              {/* soft glow behind */}
              <div className="pointer-events-none absolute -inset-6 -z-10 bg-gradient-conic opacity-60 blur-2xl" />
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}