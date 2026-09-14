type Props = {
  size?: number;
  className?: string;
};

export function Logo({ size = 28, className }: Props) {
  return (
    <span
      className={className}
      style={{ display: "inline-flex", alignItems: "center", gap: 10 }}
    >
      <svg
        width={size}
        height={size}
        viewBox="0 0 64 64"
        role="img"
        aria-label="nonce-cracker logo"
      >
        <defs>
          <linearGradient id="lg" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#F7A24A" />
            <stop offset="100%" stopColor="#E84816" />
          </linearGradient>
        </defs>
        <rect width="64" height="64" rx="14" fill="url(#lg)" />
        <path
          d="M21 18 V46"
          stroke="rgba(255,255,255,0.96)"
          strokeWidth="6"
          strokeLinecap="round"
          fill="none"
        />
        <path
          d="M21 18 L43 46"
          stroke="rgba(255,255,255,0.96)"
          strokeWidth="6"
          strokeLinecap="round"
          fill="none"
        />
        <circle cx="46" cy="18" r="3.4" fill="#ffffff" />
      </svg>
      <span className="font-semibold tracking-tight text-[15px]">
        nonce-cracker
      </span>
    </span>
  );
}