import { motion } from "framer-motion";

type Props = {
  className?: string;
};

// Renders a softly animated, abstract secp256k1-ish curve plus
// a constellation of "candidate" points and a target key.
export function CurveViz({ className }: Props) {
  // Smooth high-resolution polyline approximating y² = x³ + 7
  const N = 260;
  const x0 = -2.7;
  const x1 = 3.6;
  const w = 600;
  const h = 420;
  const cy = h / 2 + 12;
  const scaleX = (x: number) => ((x - x0) / (x1 - x0)) * w;
  const scaleY = (y: number) => cy - (y / 4) * h * 0.55;

  const upper: Array<[number, number]> = [];
  const lower: Array<[number, number]> = [];
  for (let i = 0; i <= N; i++) {
    const t = i / N;
    const x = x0 + (x1 - x0) * t;
    const disc = x * x * x + 7;
    if (disc < 0) continue;
    const y = Math.sqrt(disc);
    upper.push([scaleX(x), scaleY(y)]);
    lower.push([scaleX(x), scaleY(-y)]);
  }
  const toPath = (pts: Array<[number, number]>) =>
    pts.length ? "M " + pts.map((p) => `${p[0].toFixed(2)},${p[1].toFixed(2)}`).join(" L ") : "";

  const upperPath = toPath(upper);
  const lowerPath = toPath(lower);

  // Candidate nonce points — distributed across the search domain.
  const candidates = Array.from({ length: 22 }).map((_, i) => i);

  return (
    <div className={`relative ${className ?? ""}`}>
      <svg
        viewBox="0 0 600 420"
        className="w-full h-full"
        aria-hidden
      >
        <defs>
          <linearGradient id="curveStroke" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#F7A24A" stopOpacity="0.05" />
            <stop offset="20%" stopColor="#F7A24A" stopOpacity="0.5" />
            <stop offset="55%" stopColor="#F1823A" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#E84816" stopOpacity="0.5" />
          </linearGradient>
          <radialGradient id="curveGlow" cx="55%" cy="50%" r="55%">
            <stop offset="0%" stopColor="#F1823A" stopOpacity="0.22" />
            <stop offset="60%" stopColor="#F1823A" stopOpacity="0.05" />
            <stop offset="100%" stopColor="#F1823A" stopOpacity="0" />
          </radialGradient>
          <radialGradient id="targetGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.95" />
            <stop offset="40%" stopColor="#F7A24A" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#F1823A" stopOpacity="0" />
          </radialGradient>
          <linearGradient id="scan" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="rgba(241,130,58,0)" />
            <stop offset="50%" stopColor="rgba(241,130,58,0.55)" />
            <stop offset="100%" stopColor="rgba(241,130,58,0)" />
          </linearGradient>
          <filter id="soft" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="2.5" />
          </filter>
        </defs>

        {/* Ambient glow */}
        <ellipse cx="330" cy="220" rx="300" ry="180" fill="url(#curveGlow)" />

        {/* Faint grid */}
        <g stroke="rgba(255,255,255,0.04)" strokeWidth="1">
          {Array.from({ length: 13 }).map((_, i) => (
            <line
              key={`vx-${i}`}
              x1={(i / 12) * 600}
              y1={0}
              x2={(i / 12) * 600}
              y2={420}
            />
          ))}
          {Array.from({ length: 9 }).map((_, i) => (
            <line
              key={`hy-${i}`}
              x1={0}
              y1={(i / 8) * 420}
              x2={600}
              y2={(i / 8) * 420}
            />
          ))}
        </g>

        {/* Curve — animated draw-on */}
        <motion.path
          d={upperPath}
          fill="none"
          stroke="url(#curveStroke)"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          initial={{ pathLength: 0, opacity: 0 }}
          animate={{ pathLength: 1, opacity: 1 }}
          transition={{ duration: 2.2, ease: [0.65, 0, 0.35, 1] }}
        />
        <motion.path
          d={lowerPath}
          fill="none"
          stroke="url(#curveStroke)"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          initial={{ pathLength: 0, opacity: 0 }}
          animate={{ pathLength: 1, opacity: 1 }}
          transition={{ duration: 2.2, ease: [0.65, 0, 0.35, 1], delay: 0.1 }}
        />

        {/* Soft halo around curve */}
        <motion.path
          d={upperPath}
          fill="none"
          stroke="url(#curveStroke)"
          strokeWidth="6"
          strokeLinecap="round"
          filter="url(#soft)"
          initial={{ pathLength: 0, opacity: 0 }}
          animate={{ pathLength: 1, opacity: 0.3 }}
          transition={{ duration: 2.2, ease: [0.65, 0, 0.35, 1] }}
        />
        <motion.path
          d={lowerPath}
          fill="none"
          stroke="url(#curveStroke)"
          strokeWidth="6"
          strokeLinecap="round"
          filter="url(#soft)"
          initial={{ pathLength: 0, opacity: 0 }}
          animate={{ pathLength: 1, opacity: 0.3 }}
          transition={{ duration: 2.2, ease: [0.65, 0, 0.35, 1], delay: 0.1 }}
        />

        {/* Scan line */}
        <motion.rect
          x={0}
          y={0}
          width={140}
          height={420}
          fill="url(#scan)"
          initial={{ x: -140 }}
          animate={{ x: 600 }}
          transition={{ duration: 4.5, repeat: Infinity, ease: "linear" }}
          opacity={0.5}
        />

        {/* Candidate points */}
        {candidates.map((c, i) => {
          const baseX = 50 + i * 24 + ((i * 13) % 17);
          const baseY = 90 + ((i * 53) % 240);
          return (
            <motion.g
              key={c}
              initial={{ opacity: 0 }}
              animate={{
                opacity: [0, 0.85, 0.4, 0.85, 0],
                transform: [
                  `translate(0px, -10px)`,
                  `translate(0px, 0px)`,
                  `translate(0px, 8px)`,
                  `translate(0px, 0px)`,
                  `translate(0px, -6px)`,
                ],
              }}
              transition={{
                duration: 3 + (i % 3) * 0.6,
                repeat: Infinity,
                ease: "easeInOut",
                delay: i * 0.15,
              }}
            >
              <circle cx={baseX} cy={baseY} r={2.2} fill="#F1823A" />
              <circle cx={baseX} cy={baseY} r={4} fill="#F1823A" opacity={0.18} />
            </motion.g>
          );
        })}

        {/* Target public key — Q = d·G */}
        <motion.circle
          cx={470}
          cy={140}
          r={20}
          fill="url(#targetGlow)"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.4, duration: 0.6 }}
        />
        <motion.circle
          cx={470}
          cy={140}
          r={6}
          fill="#fff"
          stroke="#F1823A"
          strokeWidth={1.5}
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: [0.8, 1.4, 0.8], opacity: 1 }}
          transition={{
            duration: 2.4,
            repeat: Infinity,
            ease: "easeInOut",
            delay: 1.4,
          }}
        />
        <motion.circle
          cx={470}
          cy={140}
          r={14}
          fill="none"
          stroke="#F1823A"
          strokeWidth={1}
          initial={{ opacity: 0 }}
          animate={{ opacity: [0, 0.5, 0], r: [6, 22, 32] }}
          transition={{ duration: 2.4, repeat: Infinity, ease: "easeOut", delay: 1.4 }}
        />
      </svg>

      <div className="pointer-events-none absolute inset-0 mask-fade-b" />
    </div>
  );
}

export default CurveViz;