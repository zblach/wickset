# wickset — wire format, version 1

A wick: a sequential delay. A secret `S` is masked behind `N+1` inherently
sequential evaluations of a step function `H`, burned one at a time. Anyone
can lengthen the wick without learning `S`. This document specifies the wick
only: no library API, CLI, container, UI or payload encryption is part of the
format.

## 1. Notation

* `B` — block length in bytes, a property of the algorithm (§3).
* `I[0..N]` — the wick's values, each `B` bytes.
* `O[j] = H(I[j])` — step outputs, each `B` bytes.
* `⊕` — bytewise XOR. `‖` — concatenation.
* `len(S) = len(I[j]) = len(O[j]) = B`.

## 2. Wick

```
wick   = ALG_ID(1) ‖ blocks
blocks = (S ⊕ O[0]) ‖ (I[0] ⊕ O[1]) ‖ (I[1] ⊕ O[2]) ‖ … ‖ (I[N-1] ⊕ O[N]) ‖ I[N]
```

The wick is `N+2` blocks of `B` bytes, numbered from `S`: `block 0 = S ⊕ O[0]`,
`block j = I[j-1] ⊕ O[j]` for `j = 1..N`, `block N+1 = I[N]` (the only
plaintext value, where burning starts). There is no length prefix, count,
version byte, check byte, padding or terminator. Framing belongs to the
embedding protocol.

```
len(wick) = 1 + (N+2)·B        N = (len(wick) − 1)/B − 2        N ≥ 0
```

`N = 0` is valid: `ALG_ID ‖ (S ⊕ O[0]) ‖ I[0]`, a single step.

## 3. Algorithm registry (closed)

`ALG_ID` selects a complete definition of the step function `H` and everything
it needs. There are no free parameters. The format assumes only that an entry
supplies a block length `B` and an `H` mapping `B` bytes to `B` bytes. It
assumes nothing about how `H` works: a future entry need not be Argon2, need not
take a salt, and need not share any metadata with another entry. Each entry
defines its own parameters, including any salt or domain string it uses.

| ID          | B  | Definition | Status |
|-------------|----|------------|--------|
| `0x00`      | —  | —          | **invalid** |
| `0x01`      | 32 | §3.1       | defined |
| `0x02`      | 32 | §3.2       | defined |
| `0x03`      | 32 | §3.3       | defined |
| `0x04`      | 32 | §3.4       | defined |
| `0x05–0xEF` | —  | —          | unassigned |
| `0xF0–0xFF` | —  | —          | private use, never assigned |

Any `ALG_ID` not marked "defined" is rejected before any other work (this
covers `0x00`, unassigned IDs and the private-use range alike). Implementations
may use `0xF0–0xFF` privately for testing; such wicks are not interoperable
and no conformance vector uses them. A new parameter set or primitive is a new
`ALG_ID`; a layout change is a new format.

Every value in an entry belongs to that entry; nothing is a global constant.
Each entry that takes a salt or domain string includes its own `ALG_ID` in it.

The entries come in pairs of one primitive, a short step and a long one.
A wick's delay is its step count times its step time, so a longer step
makes a given delay a smaller wick (`B` bytes per step). How the parameters
were chosen is not part of this specification.

### 3.1 `0x01`

```
H(x) = Argon2id(password = x, salt = "wickset/v1::0x01", secret = ε, ad = ε,
                m = 131072 KiB, t = 5, p = 1, outLen = 32)
```

Argon2id v1.3 per RFC 9106, version 0x13. The salt is the ASCII string above,
16 bytes (the salt length common Argon2id APIs require, such as libsodium's),
the same for every step of every wick of this entry, so steps are
deliberately not bound to position, wick or length, and the wick can be
lengthened (§7). The `v1` is domain separation only: the wick carries no
version, and a format change is signalled by the container. `p = 1` so a
single step cannot be spread across cores.

### 3.2 `0x02`

As §3.1, except `salt = "wickset/v1::0x02"` and `t = 192`.

### 3.3 `0x03`

```
h[1] = SHA-256("wickset/v1::0x03" ‖ x)
h[i] = SHA-256(h[i-1])            for i = 2..K
H(x) = h[K]                       K = 2^24
```

SHA-256 per FIPS 180-4. The domain string is the ASCII string above, 16
bytes, constant as §3.1's salt is; each later hash is of the 32-byte digest
before it. `H` is `K` hashes in sequence and nothing else: no memory beyond
one digest.

### 3.4 `0x04`

As §3.3, except the domain string is `"wickset/v1::0x04"` and `K = 2^29`.

## 4. Step function

`H` is defined per registry entry (§3), takes `B` bytes and returns `B` bytes.
The format uses it only through that signature.

## 5. Create

1. Draw `I[0..N]`, each `B` bytes, uniformly random and independent.
2. `O[j] = H(I[j])` for `j = 0..N` (independent, so parallelizable).
3. Emit `ALG_ID ‖ (S ⊕ O[0]) ‖ (I[0] ⊕ O[1]) ‖ … ‖ (I[N-1] ⊕ O[N]) ‖ I[N]`.
4. Discard `I[0..N-1]` and every `O`.

How the `I[j]` are produced is outside the format, provided they are uniform
random and independent. Creator CPU time equals solver CPU time; the creator
saves only wall-clock, by running step 2 in parallel.

## 6. Burn (solve)

```
x = block N+1                          # I[N]
for j = N down to 1:
    x = block j ⊕ H(x)                 # I[j-1]
S = block 0 ⊕ H(x)                     # H(I[0]) = O[0]
```

`N+1` sequential evaluations, from the last block toward block 0. State
between steps is `(j, x)`, and it is itself a wick: after burning down to
`I[j-1]`, the bytes `ALG_ID ‖ block 0 ‖ … ‖ block j-1 ‖ I[j-1]` are a valid
wick with `N' = j-1` that burns to the same `S`. A partly burned wick is a
prefix of the original with one new last block, so burning is resumable from
a saved copy, and a copy can be recognized as the original's by that prefix.
The format carries no check on `S` or on any intermediate value: success is
established only by authenticating whatever `S` protects.

## 7. Extend (add steps, no secret required)

Given a wick with `N`, let `I[N]` be its last block. Draw fresh uniform
random `I[N+1..M]` (`M > N`), compute `O[j] = H(I[j])` for `j = N+1..M`, drop
the last block and append:

```
… ‖ (I[N-1] ⊕ O[N]) ‖ (I[N] ⊕ O[N+1]) ‖ (I[N+1] ⊕ O[N+2]) ‖ … ‖ (I[M-1] ⊕ O[M]) ‖ I[M]
```

Existing blocks are untouched, and keep their numbers. The extender learns
neither `S` nor any earlier `O`, and the solver burns the new part first, so
delay adds serially. `ALG_ID` is unchanged. Extension is unauthenticated:
anyone holding a wick can lengthen it.

## 8. Parser rules

A wick is rejected, before any evaluation of `H`, unless all of:

1. `len ≥ 1` and `ALG_ID` is a defined algorithm.
2. `(len − 1)` is an exact multiple of `B`, and `(len − 1)/B ≥ 2`.

There is no trailing data, padding or alternate encoding: one valid byte
string per wick. Parse the bytes as received. The format sets no upper bound
on `N`; resource limits are a local policy of the verifier.

## 9. What `S` protects (informative)

`S` is a `B`-byte key. The payload is encrypted outside this format, e.g. for
`B = 32`: AES-256-GCM under `S` with a random nonce carried in the payload
(Go: `cipher.NewGCMWithRandomNonce`). The wick yields `S` and nothing else;
the payload's own authentication is the only success signal. Nesting is a
payload whose plaintext is another wick.

## 10. Security considerations

* **Hardware-relative.** Delay is wall-clock on the solver's hardware, and the
  clock starts when burning starts, not when the wick was created. Calibrate
  for the fastest plausible adversary.
* **Memory-hardness.** The Argon2id entries (`0x01`, `0x02`) make each step
  wait on memory rather than arithmetic, which narrows but does not remove the
  advantage of dedicated hardware; a working set that fits a solver's cache
  narrows it less. The SHA-256 entries (`0x03`, `0x04`) are not memory-hard: a
  solver with faster sequential SHA-256 than the calibrating machine's burns
  their wicks sooner in proportion.
* **Randomness.** Every `I[j]` must be uniform and independent. An algorithm's
  salt is constant across wicks, so identical `I` values in two wicks of the
  same algorithm would share work; random `I` makes that negligible.
* **Integrity and authenticity are outside the format.** Any altered,
  truncated or substituted block yields a wrong `S`, detected only at the
  payload's authentication, after the full delay. Pre-burn detection of rot,
  and scrubbing, belong to the container (a digest checked before burning);
  origin and tamper-evidence belong to a signed manifest; repair belongs to
  parity or multiple copies.
* **Extension is monotone.** It adds delay and never removes any, and it needs
  no secret. It binds only holders who never saw the pre-extension wick:
  anyone who held the original can still burn it in its original `N+1` steps.
  Its cost to the extender is linear in the delay added (parallelizable, not
  shortcut-able).
* **Partly burned wicks are shortcuts.** A saved partial burn (§6) opens in
  the steps it has left. It reveals nothing a solver would not reach by
  burning, but whoever holds it is that much closer to `S`; a published one
  that is not genuine wastes the time of whoever trusts it.
* **Quantum.** No algebraic structure is used; there is no known useful quantum
  speedup of iterated sequential hashing.
