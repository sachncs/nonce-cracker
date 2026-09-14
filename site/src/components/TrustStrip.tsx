import { Reveal, Stagger, StaggerItem } from "./Reveal";
import { TRUST_ITEMS } from "../lib/content";

export function TrustStrip() {
  return (
    <section className="relative border-y border-white/[0.05] bg-ink-900/40">
      <div className="container-x py-7 md:py-8">
        <Stagger className="grid grid-cols-2 md:grid-cols-4 gap-x-8 gap-y-5">
          {TRUST_ITEMS.map((t, i) => (
            <StaggerItem
              key={t.label}
              index={i}
              className="flex items-center gap-3 text-[13px] text-white/65"
            >
              <span className="inline-flex h-1.5 w-1.5 rounded-full bg-accent-500" />
              <div>
                <div className="text-white/85 font-medium tracking-tight">
                  {t.label}
                </div>
                <div className="text-[11px] uppercase tracking-[0.16em] text-white/40 mt-0.5">
                  {t.hint}
                </div>
              </div>
            </StaggerItem>
          ))}
        </Stagger>
      </div>
    </section>
  );
}