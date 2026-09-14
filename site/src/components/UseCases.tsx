import { Reveal, Stagger, StaggerItem } from "./Reveal";
import { USE_CASES } from "../lib/content";

export function UseCases() {
  return (
    <section
      id="use-cases"
      className="relative py-24 md:py-36 scroll-mt-20 border-t border-white/[0.05]"
    >
      <div className="container-x">
        <Reveal>
          <div className="max-w-2xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 text-[11.5px] uppercase tracking-[0.18em] text-white/60">
              <span className="h-1.5 w-1.5 rounded-full bg-accent-500" />
              Built for
            </div>
            <h2 className="mt-5 font-display text-display-lg tracking-tighter text-balance">
              Honest cryptography, in{" "}
              <span className="text-white/55">the right hands.</span>
            </h2>
            <p className="mt-5 text-[16.5px] leading-[1.6] text-white/60">
              Nonce bias is a real protocol failure, not a thought experiment.
              The tool exists to make those failures cheap to reproduce —
              before someone else can exploit them in production.
            </p>
          </div>
        </Reveal>

        <Stagger className="mt-12 md:mt-16 grid grid-cols-1 md:grid-cols-3 gap-4">
          {USE_CASES.map((u, i) => (
            <StaggerItem key={u.title} index={i}>
              <article className="group relative h-full rounded-2xl border border-white/[0.07] bg-gradient-to-b from-white/[0.03] to-white/[0.005] p-6 md:p-7 transition-all hover:border-white/[0.14]">
                <div className="absolute top-5 right-5 font-mono text-[11px] text-white/30 tracking-tight">
                  0{i + 1}
                </div>
                <h3 className="text-[18px] font-semibold tracking-tight text-white">
                  {u.title}
                </h3>
                <p className="mt-3 text-[14.5px] leading-[1.55] text-white/60">
                  {u.body}
                </p>
                <div className="mt-6 h-px bg-gradient-to-r from-transparent via-white/[0.08] to-transparent" />
                <div className="mt-4 inline-flex items-center gap-2 text-[12px] uppercase tracking-[0.16em] text-white/40">
                  <span className="h-1 w-6 bg-accent-500/70" />
                  ETHICAL USE
                </div>
              </article>
            </StaggerItem>
          ))}
        </Stagger>

        <Reveal delay={0.1}>
          <div className="mt-12 rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5 md:p-6">
            <div className="flex items-start gap-4">
              <div className="shrink-0 mt-0.5 h-7 w-7 rounded-full bg-accent-500/15 border border-accent-500/30 grid place-items-center">
                <span className="text-accent-400 text-[12px] font-semibold">!</span>
              </div>
              <div>
                <div className="text-[14.5px] font-medium text-white/85">
                  Authorized use only
                </div>
                <p className="mt-1 text-[13.5px] leading-[1.6] text-white/55 max-w-[760px]">
                  nonce-cracker is intended for protocol research, security
                  auditing, and education. Do not run it against signatures or
                  wallets you do not own. The author is not responsible for
                  misuse.
                </p>
              </div>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}