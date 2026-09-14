import { CodeBlock } from "./CodeBlock";
import { Reveal } from "./Reveal";
import { CLI_RUN } from "../lib/content";

export function Cli() {
  return (
    <section
      id="cli"
      className="relative py-24 md:py-36 scroll-mt-20 border-t border-white/[0.05]"
    >
      <div className="container-x">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
          <Reveal className="lg:col-span-5">
            <div className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 text-[11.5px] uppercase tracking-[0.18em] text-white/60">
              <span className="h-1.5 w-1.5 rounded-full bg-accent-500" />
              CLI
            </div>
            <h2 className="mt-5 font-display text-display-lg tracking-tighter text-balance">
              One command, every search.
            </h2>
            <p className="mt-5 text-[16.5px] leading-[1.6] text-white/60">
              Pass the signature triplet, the target public key, and a search
              range. The engine handles parsing, validation, affine-constant
              derivation, algorithm dispatch, parallelism, and graceful
              shutdown — and writes a structured report when it's done.
            </p>
            <ul className="mt-7 space-y-2.5 text-[14px] text-white/65">
              {[
                "Decimal or 0x-prefixed hex for every numeric input",
                "Compressed (02/03) or uncompressed (04) public keys",
                "Signed ranges with --offset for nonces near n/2",
                "Per-call thread budget via --threads",
              ].map((b) => (
                <li key={b} className="flex items-start gap-2.5">
                  <span className="mt-[7px] h-1.5 w-1.5 rounded-full bg-accent-500 shrink-0" />
                  <span>{b}</span>
                </li>
              ))}
            </ul>
          </Reveal>

          <Reveal className="lg:col-span-7" delay={0.05}>
            <CodeBlock
              code={CLI_RUN}
              title="nonce-cracker run — search a custom range"
            />
          </Reveal>
        </div>
      </div>
    </section>
  );
}