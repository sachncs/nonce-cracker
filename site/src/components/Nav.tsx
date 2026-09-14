import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Menu, X, Github } from "lucide-react";
import { Logo } from "./Logo";
import { NAV_LINKS, REPO } from "../lib/content";

export function Nav() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={`fixed top-0 inset-x-0 z-50 transition-colors duration-300 ${
        scrolled
          ? "bg-ink-950/70 backdrop-blur-xl border-b border-white/[0.06]"
          : "bg-transparent border-b border-transparent"
      }`}
    >
      <div className="container-x flex h-[68px] items-center justify-between">
        <a
          href="#top"
          className="flex items-center text-white/90 hover:text-white transition-colors"
          aria-label="nonce-cracker home"
        >
          <Logo size={26} />
        </a>

        <nav className="hidden md:flex items-center gap-1">
          {NAV_LINKS.map((l) => (
            <a
              key={l.href}
              href={l.href}
              className="px-3.5 py-2 text-[13.5px] text-white/65 hover:text-white transition-colors rounded-full hover:bg-white/[0.04]"
            >
              {l.label}
            </a>
          ))}
        </nav>

        <div className="hidden md:flex items-center gap-2">
          <a
            href={`${REPO.url}#installation`}
            className="text-[13.5px] text-white/65 hover:text-white px-3.5 py-2 transition-colors"
          >
            Install
          </a>
          <a
            href={REPO.url}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 rounded-full bg-white/[0.06] hover:bg-white/[0.1] border border-white/[0.08] px-3.5 py-2 text-[13.5px] text-white transition-all"
          >
            <Github size={14} />
            <span>Star on GitHub</span>
          </a>
        </div>

        <button
          aria-label="Open menu"
          className="md:hidden inline-flex h-10 w-10 items-center justify-center rounded-full border border-white/[0.08] bg-white/[0.04]"
          onClick={() => setOpen((v) => !v)}
        >
          {open ? <X size={16} /> : <Menu size={16} />}
        </button>
      </div>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="md:hidden border-t border-white/[0.06] bg-ink-950/90 backdrop-blur-xl"
          >
            <div className="container-x py-4 flex flex-col gap-1">
              {NAV_LINKS.map((l) => (
                <a
                  key={l.href}
                  href={l.href}
                  className="px-3 py-3 text-[15px] text-white/80 hover:text-white rounded-lg hover:bg-white/[0.04]"
                  onClick={() => setOpen(false)}
                >
                  {l.label}
                </a>
              ))}
              <a
                href={REPO.url}
                target="_blank"
                rel="noreferrer"
                className="mt-2 inline-flex items-center justify-center gap-2 rounded-full bg-white/[0.06] border border-white/[0.08] px-4 py-3 text-[14px] text-white"
              >
                <Github size={14} />
                <span>Star on GitHub</span>
              </a>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}