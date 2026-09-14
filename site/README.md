# nonce-cracker — site

Premium product page for the [nonce-cracker](../) Rust crate.
Built with Vite + React + TypeScript + Tailwind CSS + Framer Motion.

## Develop

```bash
cd site
npm install
npm run dev
```

The dev server runs on http://localhost:5173.

## Build

```bash
npm run build
```

Outputs to `site/dist/`. The repository's GitHub Actions workflow at
`.github/workflows/pages.yml` builds the site on every push to `master`
and publishes it via the official `actions/deploy-pages` action.

## Deploy

GitHub Pages must be configured to deploy from **GitHub Actions** in
Settings → Pages. The included workflow handles builds, asset
fingerprinting, and `nojekyll` automatically.

## Structure

```
site/
├── index.html              # Vite entry
├── public/
│   ├── favicon.svg         # Browser tab icon
│   ├── logo.svg            # Brand mark (used by README too)
│   └── og.svg              # Open Graph card
├── src/
│   ├── main.tsx            # React root
│   ├── App.tsx             # Page composition
│   ├── index.css           # Tailwind + design tokens
│   ├── components/         # Section components
│   └── lib/
│       ├── content.ts      # Marketing copy and config
│       └── utils.ts        # cn() helper
├── tailwind.config.js
├── postcss.config.js
├── vite.config.ts
└── tsconfig.json
```