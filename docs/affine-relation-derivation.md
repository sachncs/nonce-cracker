# Affine Relation Derivation

This document proves the correctness of `derive_affine_constants` for the
single-signature ECDSA nonce-search attack implemented in `crypto.rs`.

## Assumptions

Let:

- `n` be the secp256k1 curve order
- `d` be the private key
- `z` be the message hash reduced modulo `n`
- `r` be the ECDSA `r` value
- `s` be the ECDSA `s` value
- `k` be the nonce used to produce the signature
- `G` be the generator point
- `Q = d * G` be the public key

ECDSA gives:

```text
r = (k * G).x mod n
s = k^-1 (z + r d) mod n
```

## Step 1: Solve for the private key `d`

Starting from the signature equation:

```text
s = k^-1 (z + r d) mod n
```

Multiply both sides by `k`:

```text
s k = z + r d   (mod n)
```

Rearrange to isolate `d`:

```text
r d = s k - z   (mod n)
```

If `r` is invertible modulo `n`, multiply both sides by `r^-1`:

```text
d = r^-1 s k - r^-1 z   (mod n)
```

## Step 2: Define the affine constants (positive beta form)

Define:

```text
alpha = r^-1 s   (mod n)
beta  = r^-1 z   (mod n)
```

Then:

```text
d = alpha * k - beta   (mod n)
```

This is the canonical formulation: `beta` is always positive and `d` is a line
in `k` with slope `alpha` and intercept `-beta`.

## Step 3: Reformulate as a pure multiplicative search

Let `k0 = beta * alpha^-1 (mod n)`.  This is the nonce that would make
`alpha * k - beta = 0` if it were in range.  Rewrite `d` in terms of the
displacement `delta = k - k0`:

```text
d = alpha * k - beta
  = alpha * (k0 + delta) - beta
  = alpha * k0 + alpha * delta - beta
```

Since `alpha * k0 = beta` by construction:

```text
d = alpha * delta   (mod n)
```

where `delta = k - k0 (mod n)`.

**Why this helps:** the public-key equation becomes

```text
Q = d * G = alpha * delta * G
```

so the search target is the point `delta * (alpha * G)`.  The algorithm
precomputes `T = Q` and `step_point = G * (alpha * step)`, then walks
through candidate deltas until `delta * step_point = T`.

Once a match is found, recover the nonce:

```text
k = k0 + delta   (mod n)
```

and the private key:

```text
d = alpha * k - beta   (mod n)
```

## Step 4: Match the implementation

The code computes `derive_affine_constants` as:

1. `r_inv = r.invert()` (returns `None` if `r` is not invertible)
2. `alpha = r_inv * s`
3. `beta = r_inv * z`

This matches the positive-beta form above directly, so

```text
d = alpha * k - beta
```

The search logic uses `k0 = beta * alpha^-1`, which is the canonical
positive-beta convention.  All downstream equations (`d = alpha * delta`,
etc.) remain unchanged.

## Step 5: Why the search works

Given the public key `Q = d * G`, substitute the affine relation:

```text
Q = (alpha * k - beta) * G
Q + beta * G = alpha * k * G
Q + beta * G = k * (alpha * G)
```

The implementation precomputes:

- `alpha` and `beta` from the signature
- The target point `T = Q + beta * G`
- The step point `step_point = G * (alpha * step)`

It then searches for an integer `k` in `[start, end]` such that:

```text
k * (alpha * G) = T
```

Which is equivalent to:

```text
(alpha * k - beta) * G = Q
```

When such a `k` is found, the private key is recovered as:

```text
d = alpha * k - beta   (mod n)
```

## Step 6: Implementation correctness

All operations are performed directly in the secp256k1 scalar field using the
`k256::Scalar` type, which automatically reduces every intermediate value
modulo `n`. Because the field is prime, every nonzero element has a unique
multiplicative inverse.

The only nontrivial precondition is invertibility of `r` modulo `n`. When `r`
has no inverse, the implementation returns `CryptoError::RNotInvertible`
instead of fabricating a candidate key.

## Signed search range

The search code treats `k` as a bounded signed integer, but the math is still
modulo `n`. A negative `k` is just the additive inverse of its positive
magnitude in the scalar field, so the same derivation applies.

The implementation computes `d(k)` for negative `k` as:

```text
d = -(alpha * |k|) - beta   (mod n)
```

which is equivalent to `alpha * k - beta` because `k = -|k|`.

## Complexity

- **Derivation time:** Dominated by one scalar inversion (extended Euclidean
  algorithm) and a handful of field multiplications/additions.
- **Derivation space:** Constant — only a few `Scalar` temporaries.
- **Search mapping:** The derived equation requires one affine evaluation per
  candidate, which matches the `O(N)` scan loop or `O(sqrt(N))` BSGS loop in
  `src/search/mod.rs`.
