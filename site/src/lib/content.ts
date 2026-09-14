export function cn(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(" ");
}

export const REPO = {
  name: "nonce-cracker",
  user: "sachncs",
  url: "https://github.com/sachncs/nonce-cracker",
  version: "0.6.0",
  license: "MIT",
};

export const NAV_LINKS = [
  { href: "#features", label: "Features" },
  { href: "#algorithm", label: "Algorithm" },
  { href: "#performance", label: "Performance" },
  { href: "#use-cases", label: "Use cases" },
] as const;

export const TRUST_ITEMS = [
  { label: "Rust 1.87+", hint: "Stable channel" },
  { label: "MIT License", hint: "Open source" },
  { label: "macOS · Linux · Windows", hint: "Cross-platform" },
  { label: "Zero external services", hint: "Offline by design" },
];

export const FEATURES = [
  {
    title: "Single-signature attack",
    body:
      "Recover a private key from one secp256k1 signature, public key, and message hash. No second signature, weak PRNG, or chosen-message oracle required.",
    icon: "key",
  },
  {
    title: "Three-tier algorithm dispatch",
    body:
      "Parallel scan for N ≤ 2³², parallel BSGS up to 2⁵², and Pollard's kangaroo for massive ranges. The engine picks the optimal algorithm for every search.",
    icon: "ladder",
  },
  {
    title: "Native secp256k1 arithmetic",
    body:
      "Built directly on the k256 crate with projective-coordinate hashing. No BigInt overhead, no field inversions in any hot loop.",
    icon: "atom",
  },
  {
    title: "Compact OpenMap table",
    body:
      "Custom open-addressing hash map replaces FxHashMap in the BSGS baby-step table. ~25% memory savings at scale, sharded for lock-free parallelism.",
    icon: "table",
  },
  {
    title: "Production-grade hygiene",
    body:
      "Structured tracing logs, sensitive-scalar zeroization, cargo-deny supply-chain gating, multi-platform CI, and graceful SIGINT/SIGTERM handling.",
    icon: "shield",
  },
  {
    title: "Single-command CLI",
    body:
      "One `run` invocation with `--r`, `--s`, `--z`, `--pubkey`, `--start`, `--end`. Decimal or hex input, signed ranges, and a self-contained demo mode.",
    icon: "terminal",
  },
];

export const ALGORITHMS = [
  {
    range: "N ≤ 2³²",
    label: "Parallel scan",
    summary:
      "Direct brute-force with projective point equality. Batch-dispatched across worker threads.",
    complexity: "O(N) time · O(1) per-worker memory",
    fallback: false,
  },
  {
    range: "2³² < N ≤ 2⁵²",
    label: "Parallel BSGS",
    summary:
      "Baby-step giant-step with batched projective normalization and a sharded OpenMap table.",
    complexity: "O(√N) time · O(√N) memory",
    fallback: false,
  },
  {
    range: "N > 2⁵²",
    label: "Pollard's kangaroo",
    summary:
      "Distinguished-point random walk with projective-coordinate hashing — eliminates field inversions per iteration.",
    complexity: "O(√N) expected · O(√N / 2ᵈ) memory",
    fallback: true,
  },
];

export const PERFORMANCE = [
  { range: "2³²", algo: "Parallel scan", wall: "14 ms", mem: "10 MB" },
  { range: "2⁴⁸", algo: "BSGS", wall: "3.1 s", mem: "0.5 GB" },
  { range: "2⁵²", algo: "BSGS", wall: "112 s", mem: "3 GB" },
  { range: "2⁵⁶", algo: "Kangaroo", wall: "2–5 s", mem: "10–50 MB" },
];

export const USE_CASES = [
  {
    title: "Protocol researchers",
    body:
      "Validate that Bitcoin, Ethereum, and secp256k1-based signing stacks never leak entropy into the nonce. Reproduce published attacks on weak PRNGs.",
  },
  {
    title: "Security engineers",
    body:
      "Audit hardware wallets, embedded signers, and constrained devices. Confirm that biased nonces do not enter an attacker's recoverable window.",
  },
  {
    title: "Cryptography students",
    body:
      "An honest, well-documented reference for the affine-relation attack. Self-contained demo, end-to-end tests, and clear mathematical derivations.",
  },
];

export const FOOTER_LINKS = {
  product: [
    { href: "#features", label: "Features" },
    { href: "#algorithm", label: "Algorithm" },
    { href: "#performance", label: "Performance" },
  ],
  resources: [
    {
      href: "https://github.com/sachncs/nonce-cracker#installation",
      label: "Installation",
    },
    {
      href: "https://github.com/sachncs/nonce-cracker#quick-start",
      label: "Quick start",
    },
    {
      href: "https://github.com/sachncs/nonce-cracker/blob/master/docs/affine-relation-derivation.md",
      label: "Math derivation",
    },
    {
      href: "https://github.com/sachncs/nonce-cracker/blob/master/CHANGELOG.md",
      label: "Changelog",
    },
  ],
  project: [
    {
      href: "https://github.com/sachncs/nonce-cracker/issues",
      label: "Issues",
    },
    {
      href: "https://github.com/sachncs/nonce-cracker/security/advisories/new",
      label: "Security",
    },
    {
      href: "https://github.com/sachncs/nonce-cracker/blob/master/LICENSE",
      label: "MIT license",
    },
  ],
};

export const CLI_RUN = `nonce-cracker run \\
  --r 0x37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba \\
  --s 0xe026eb94e61bcdc41f0ee8cd7b97eda899ce5856d3a32360d742b13d717ff2a8 \\
  --z 0x0000000000000000000000000000000000000000000000000000000000000001 \\
  --pubkey 03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f \\
  --start 0 --end 10000 --threads 8`;