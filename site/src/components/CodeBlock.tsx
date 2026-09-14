import { motion } from "framer-motion";
import { Copy, Check } from "lucide-react";
import { useState } from "react";

type Props = {
  code: string;
  title?: string;
  caption?: string;
  variant?: "default" | "log";
};

const EASE = [0.16, 1, 0.3, 1] as const;

// Lightweight syntax highlighter for the CLI demo.
// Recognizes: keywords, comments, hex literals, flags, strings.
function highlight(line: string): React.ReactNode {
  // Comments first
  if (line.trim().startsWith("#")) {
    return <span className="text-white/35 italic">{line}</span>;
  }

  const tokens: React.ReactNode[] = [];
  let i = 0;
  let key = 0;

  const push = (cls: string, value: string) => {
    if (!value) return;
    tokens.push(
      <span key={key++} className={cls}>
        {value}
      </span>
    );
  };

  while (i < line.length) {
    const rest = line.slice(i);
    // Strings
    const str = rest.match(/^("[^"]*"|'[^']*')/);
    if (str) {
      push("text-amber-200/85", str[0]);
      i += str[0].length;
      continue;
    }
    // Hex / numbers
    const num = rest.match(/^(0x[0-9a-fA-F]+|\d[\d_a-zA-Z]*)/);
    if (num) {
      push("text-accent-300", num[0]);
      i += num[0].length;
      continue;
    }
    // Flags
    const flag = rest.match(/^(--?[a-zA-Z][\w-]*)/);
    if (flag) {
      push("text-sky-300/90", flag[0]);
      i += flag[0].length;
      continue;
    }
    // Punctuation / operators
    const op = rest.match(/^(\\)/);
    if (op) {
      push("text-white/40", op[0]);
      i += op[0].length;
      continue;
    }
    // Default char
    push("", line[i]);
    i += 1;
  }

  return tokens;
}

export function CodeBlock({ code, title, caption }: Props) {
  const [copied, setCopied] = useState(false);
  const lines = code.split("\n");

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="relative rounded-3xl border border-white/[0.07] bg-gradient-to-b from-white/[0.025] to-white/[0.005] overflow-hidden shadow-soft">
      {/* Title bar */}
      <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-full bg-white/[0.12]" />
          <span className="h-2.5 w-2.5 rounded-full bg-white/[0.12]" />
          <span className="h-2.5 w-2.5 rounded-full bg-white/[0.12]" />
          <span className="ml-2 text-[11.5px] uppercase tracking-[0.16em] text-white/40">
            {title ?? "terminal"}
          </span>
        </div>
        <button
          type="button"
          onClick={onCopy}
          className="inline-flex items-center gap-1.5 rounded-md border border-white/[0.08] bg-white/[0.03] px-2.5 py-1 text-[11.5px] text-white/65 hover:text-white hover:bg-white/[0.06] transition-colors"
          aria-label="Copy command"
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>

      <pre className="px-5 md:px-6 py-5 md:py-6 font-mono text-[12.5px] md:text-[13.5px] leading-[1.7] overflow-x-auto">
        {lines.map((line, idx) => (
          <motion.div
            key={idx}
            initial={{ opacity: 0, x: -6 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.4, delay: idx * 0.04, ease: EASE }}
            className="flex"
          >
            <span className="select-none mr-4 inline-block w-5 text-right text-white/25">
              {idx + 1}
            </span>
            <span className="whitespace-pre">{highlight(line)}</span>
          </motion.div>
        ))}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ delay: lines.length * 0.04 + 0.2, duration: 0.4 }}
          className="flex"
        >
          <span className="mr-4 inline-block w-5" />
          <span className="inline-block h-4 w-2 bg-accent-400/80 animate-pulse" />
        </motion.div>
      </pre>

      {caption && (
        <div className="border-t border-white/[0.06] px-5 py-3 text-[12px] text-white/40">
          {caption}
        </div>
      )}
    </div>
  );
}