import { Github } from "lucide-react";
import { Logo } from "./Logo";
import { FOOTER_LINKS, REPO } from "../lib/content";

export function Footer() {
  return (
    <footer className="relative border-t border-white/[0.05] bg-ink-950">
      <div className="container-x py-16 md:py-20">
        <div className="grid grid-cols-2 md:grid-cols-12 gap-y-10 gap-x-8">
          <div className="col-span-2 md:col-span-5">
            <Logo size={28} />
            <p className="mt-5 max-w-[360px] text-[13.5px] leading-[1.6] text-white/55">
              High-speed parallel ECDSA private key recovery for secp256k1.
              Built in Rust for protocol researchers, security engineers, and
              cryptography students.
            </p>
            <a
              href={REPO.url}
              target="_blank"
              rel="noreferrer"
              className="mt-6 inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.06] px-3.5 py-2 text-[13px] text-white/80 hover:text-white transition-colors"
            >
              <Github size={13} />
              <span>{REPO.user}/{REPO.name}</span>
            </a>
          </div>

          <FooterCol title="Product" links={FOOTER_LINKS.product} />
          <FooterCol title="Resources" links={FOOTER_LINKS.resources} />
          <FooterCol title="Project" links={FOOTER_LINKS.project} />
        </div>

        <div className="mt-14 pt-6 border-t border-white/[0.06] flex flex-col-reverse md:flex-row md:items-center md:justify-between gap-4">
          <div className="text-[12.5px] text-white/40">
            © {new Date().getFullYear()} {REPO.user}. Released under the {REPO.license} License.
          </div>
          <div className="text-[12.5px] text-white/40 font-mono">
            v{REPO.version} · secp256k1 · rust 1.87+
          </div>
        </div>
      </div>
    </footer>
  );
}

function FooterCol({
  title,
  links,
}: {
  title: string;
  links: { href: string; label: string }[];
}) {
  return (
    <div className="col-span-1 md:col-span-2">
      <div className="text-[11px] uppercase tracking-[0.18em] text-white/40">
        {title}
      </div>
      <ul className="mt-4 space-y-2.5">
        {links.map((l) => (
          <li key={l.label}>
            <a
              href={l.href}
              target={l.href.startsWith("http") ? "_blank" : undefined}
              rel={l.href.startsWith("http") ? "noreferrer" : undefined}
              className="text-[13.5px] text-white/70 hover:text-white transition-colors"
            >
              {l.label}
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}