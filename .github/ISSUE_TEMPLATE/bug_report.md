---
name: Bug Report
about: Report a bug to help us improve nonce-cracker
title: '[Bug]: '
labels: bug
assignees: ''
---

## Description

A clear and concise description of the bug.

## Steps to Reproduce

1. Run command '...'
2. With options '...'
3. Observe error

## Expected Behavior

A clear description of what you expected to happen.

## Actual Behavior

What actually happened instead, including any error messages or output.

## Environment

- **nonce-cracker version**: (e.g., 0.6.0 — run `nonce-cracker --version`)
- **Rust version**: (e.g., 1.78.0 — run `rustc --version`)
- **OS**: (e.g., macOS 14.5, Ubuntu 24.04, Windows 11)
- **Architecture**: (e.g., x86_64, aarch64)
- **CPU cores**: (e.g., 8)

## Input Data

If applicable, provide the exact command and inputs:

```bash
nonce-cracker run \
  --r 0x... \
  --s 0x... \
  --z 0x... \
  --pubkey 0x... \
  --start 0 \
  --end 10000
```

## Logs

If applicable, include relevant log output:

```
<paste log output here>
```

## Additional Context

Add any other context about the problem here (screenshots, related issues, etc.).

## Checklist

- [ ] I am using the latest version of nonce-cracker
- [ ] I have searched existing issues to avoid duplicates
- [ ] I have included all relevant environment information
- [ ] I can reproduce this issue with the steps above
