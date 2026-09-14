import { Reveal, Stagger, StaggerItem } from "./Reveal";
import { PERFORMANCE } from "../lib/content";

export function Performance() {
  return (
    <section
      id="performance"
      className="relative py-24 md:py-36 scroll-mt-20 border-t border-white/[0.05]"
    >
      <div className="container-x">
        <Reveal>
          <div className="max-w-2xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 text-[11.5px] uppercase tracking-[0.18em] text-white/60">
              <span className="h-1.5 w-1.5 rounded-full bg-accent-500" />
              Performance
            </div>
            <h2 className="mt-5 font-display text-display-lg tracking-tighter text-balance">
              Wall time that earns the GPU comparison.
            </h2>
            <p className="mt-5 text-[16.5px] leading-[1.6] text-white/60">
              Measured on Apple M4 (12 cores). Scaling is near-linear with
              CPU core count for sufficiently large search windows.
            </p>
          </div>
        </Reveal>

        <Reveal delay={0.05}>
          <div className="mt-12 md:mt-16">
            {/* Headline stats */}
            <Stagger className="grid grid-cols-2 md:grid-cols-4 gap-px bg-white/[0.06] rounded-3xl overflow-hidden border border-white/[0.06]">
              {[
                { value: "10⁷+", unit: "keys / sec / thread", hint: "Parallel scan" },
                { value: "O(√N)", unit: "expected", hint: "Pollard kangaroo" },
                { value: "10 GB", unit: "BSGS ceiling", hint: "with OpenMap" },
                { value: "~25%", unit: "memory savings", hint: "vs FxHashMap" },
              ].map((s, i) => (
                <StaggerItem key={s.hint} index={i}>
                  <div className="bg-ink-900/80 backdrop-blur p-6 md:p-7">
                    <div className="font-display text-[36px] md:text-[44px] font-semibold leading-none tracking-tighter text-white">
                      {s.value}
                    </div>
                    <div className="mt-3 text-[12px] uppercase tracking-[0.16em] text-white/45">
                      {s.unit}
                    </div>
                    <div className="mt-1 text-[12.5px] text-white/65">{s.hint}</div>
                  </div>
                </StaggerItem>
              ))}
            </Stagger>
          </div>
        </Reveal>

        <Reveal delay={0.1}>
          <div className="mt-10 rounded-3xl border border-white/[0.06] bg-white/[0.015] overflow-hidden">
            <div className="grid grid-cols-12 px-6 py-4 text-[11px] uppercase tracking-[0.18em] text-white/40 border-b border-white/[0.05]">
              <div className="col-span-3 md:col-span-2">Range size</div>
              <div className="col-span-4 md:col-span-3">Algorithm</div>
              <div className="col-span-3 md:col-span-3">Wall time</div>
              <div className="hidden md:block md:col-span-2">Memory</div>
              <div className="hidden md:block md:col-span-2 text-right">Scaling</div>
            </div>
            <div className="divide-y divide-white/[0.05]">
              {PERFORMANCE.map((row, i) => (
                <div
                  key={row.range}
                  className="grid grid-cols-12 px-6 py-4 text-[14px] items-center hover:bg-white/[0.02] transition-colors"
                >
                  <div className="col-span-3 md:col-span-2 font-mono text-white/85">
                    {row.range}
                  </div>
                  <div className="col-span-4 md:col-span-3 text-white/65">
                    {row.algo}
                  </div>
                  <div className="col-span-5 md:col-span-3 font-display text-[15.5px] text-accent-400">
                    {row.wall}
                  </div>
                  <div className="hidden md:block md:col-span-2 font-mono text-[13px] text-white/55">
                    {row.mem}
                  </div>
                  <div className="hidden md:flex md:col-span-2 justify-end">
                    <ScaleBar i={i} />
                  </div>
                </div>
              ))}
            </div>
            <div className="px-6 py-4 border-t border-white/[0.05] text-[11.5px] text-white/40 flex items-center justify-between">
              <span>Benchmarks from <span className="text-white/65">bench/search.rs</span> · Apple M4 · 12 cores</span>
              <span className="hidden md:inline">log-scaled wall time</span>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function ScaleBar({ i }: { i: number }) {
  const widths = [12, 38, 68, 24];
  const colors = [
    "from-accent-300 to-accent-500",
    "from-accent-300 to-accent-500",
    "from-accent-400 to-accent-600",
    "from-accent-400 to-accent-700",
  ];
  return (
    <div className="flex items-center gap-2">
      <div className="h-1 w-32 rounded-full bg-white/[0.05] overflow-hidden">
        <div
          className={`h-full bg-gradient-to-r ${colors[i]} rounded-full`}
          style={{ width: `${widths[i]}%` }}
        />
      </div>
    </div>
  );
}