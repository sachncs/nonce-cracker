# Affine Relation Derivation

This document proves that the implementation in `derive_affine_constants`
matches the two ECDSA signature equations under the nonce relation
`k2 = k1 + delta` in the scalar field modulo the secp256k1 curve order `n`.

The derivation is intentionally aligned with the code:

- `u` corresponds to the modular inverse of `s1`
- `a`, `b`, and `c` are the linear coefficients extracted from the two
  signatures
- `alpha` and `beta` are the final constants used by the search
- `delta` is the bounded signed search variable passed in by the CLI

## Assumptions

Let:

- `n` be the secp256k1 curve order
- `d` be the private key
- `z1`, `z2` be the message hashes reduced modulo `n`
- `r1`, `r2` be the ECDSA `r` values
- `s1`, `s2` be the ECDSA `s` values
- `k1` be the first nonce
- `k2 = k1 + delta` be the second nonce

ECDSA gives:

```text
s1 = k1^-1 (z1 + r1 d) mod n
s2 = k2^-1 (z2 + r2 d) mod n
```

Substituting `k2 = k1 + delta`:

```text
s1 = k1^-1 (z1 + r1 d) mod n
s2 = (k1 + delta)^-1 (z2 + r2 d) mod n
```

## Step 1: Eliminate `k1`

From the first equation:

```text
s1 k1 = z1 + r1 d   (mod n)
k1 = s1^-1 (z1 + r1 d)   (mod n)
```

Define:

```text
u = s1^-1 mod n
```

Then:

```text
k1 = u (z1 + r1 d)   (mod n)
```

## Step 2: Substitute into the second signature equation

Starting from:

```text
s2 (k1 + delta) = z2 + r2 d   (mod n)
```

Substitute `k1 = u (z1 + r1 d)`:

```text
s2 (u (z1 + r1 d) + delta) = z2 + r2 d   (mod n)
```

Expand:

```text
s2 u z1 + s2 u r1 d + s2 delta = z2 + r2 d   (mod n)
```

Move all terms involving `d` to the left and the rest to the right:

```text
(s2 u r1 - r2) d = z2 - s2 u z1 - s2 delta   (mod n)
```

This is the key linear relation.

## Step 3: Match the implementation variables

The code defines:

```text
a = s2 * r1 * u - r2   (mod n)
b = z2 - s2 * z1 * u   (mod n)
c = s2                 (mod n)
```

So the equation becomes:

```text
a d = b - c delta   (mod n)
```

If `a` is invertible modulo `n`, multiply both sides by `a^-1`:

```text
d = a^-1 (b - c delta)   (mod n)
```

Distribute:

```text
d = (a^-1 b) + (-a^-1 c) delta   (mod n)
```

Reorder terms:

```text
d = alpha * delta + beta   (mod n)
```

where:

```text
alpha = -c * a^-1   (mod n)
beta  =  b * a^-1   (mod n)
```

These are exactly the values computed by `derive_affine_constants`.

## Step 4: Why the implementation is correct

The function computes:

1. `u = modular_inverse(s1, n)`
2. `a = normalize_modulo(s2 * r1 * u - r2, n)`
3. `b = normalize_modulo(z2 - s2 * z1 * u, n)`
4. `c = normalize_modulo(s2, n)`
5. `a_inv = modular_inverse(a, n)`
6. `alpha = normalize_modulo(-c * a_inv, n)`
7. `beta = normalize_modulo(b * a_inv, n)`

Because all operations are performed modulo `n`, the normalization step does
not change the residue class, it only chooses the canonical representative in
`[0, n)`.

The search then evaluates:

```text
d(delta) = alpha * delta + beta   (mod n)
```

which is algebraically equivalent to the derived form above.

### Proof sketch

The code computes canonical residues after every modular operation. Because
canonicalization preserves residue classes modulo `n`, each intermediate value
remains mathematically equivalent to the symbol used in the derivation. The
only nontrivial precondition is invertibility of `s1` and `a` modulo `n`.
When those inverses exist, the computed `alpha` and `beta` are uniquely
defined, and the search evaluates the same affine function derived above.

## Failure condition

If `a` is not invertible modulo `n`, then the equation

```text
a d = b - c delta   (mod n)
```

does not yield a unique `d`. In that case the implementation correctly
returns an error instead of fabricating a candidate key.

## Signed delta note

The search code treats `delta` as a bounded signed integer, but the math is
still modulo `n`. A negative `delta` is just the additive inverse of its
positive magnitude in the scalar field, so the same derivation applies.

## Complexity

- **Derivation time:** dominated by two modular inversions over arbitrary
  precision integers.
- **Derivation space:** constant with respect to the input size, aside from
  temporary big integers used during the modular arithmetic.
- **Search mapping:** the derived equation is a single affine evaluation per
  candidate delta, which matches the `O(N)` search loop in `src/main.rs`.
