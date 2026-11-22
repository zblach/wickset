# wickset — file containers, version 1

SPEC.md defines the wick and leaves framing to "the embedding protocol" (§2,
§10). This document is that protocol for the wickset library and CLI: how a
wick and its payload are stored on disk. It never changes the wick; every
container carries it byte for byte.

Nothing here provides authenticity. Every digest below detects accidental
damage (rot, truncation, a mixed-up pair) and anyone can recompute it. Origin
and tamper evidence still belong to a signed manifest (SPEC.md §10).

## 1. Detection

A reader tells the forms apart by content alone, in this order:

| First bytes                             | Form                    |
|-----------------------------------------|-------------------------|
| `00 57 53 2D 57 49 43 4B` (`\0WS-WICK`) | wick file (§2)          |
| `00 57 53 2D 50 41 59 4C` (`\0WS-PAYL`) | payload file (§3)       |
| any other `00 …`                        | rejected                |
| anything else                           | raw wick (SPEC.md)      |

This is unambiguous: SPEC.md §3 makes `ALG_ID 0x00` permanently invalid, so
no raw wick starts with `00`.

## 2. Wick file

```
wickfile   = MAGIC_WICK(8) ‖ VERSION(1) ‖ DIGEST(32) ‖ wick
MAGIC_WICK = 00 57 53 2D 57 49 43 4B        "\0WS-WICK"
VERSION    = 01
DIGEST     = SHA-256(wick)
```

A reader rejects an unknown version, and rejects a digest mismatch before any
evaluation of `H`: a damaged wick fails at once instead of after the full
delay. Extending a wick file rewrites the digest, and an extender verifies the
old digest first, so it never seals damage under a fresh one.

The raw wick (SPEC.md, no header) remains valid on disk for interoperability
(`--raw`), with no digest.

## 3. Payload file

```
payload    = HEADER ‖ NONCE(12) ‖ CIPHERTEXT ‖ TAG(16) ‖ TRAILER(32)
HEADER     = MAGIC_PAYL(8) ‖ VERSION(1) ‖ WICK_ID(32)
MAGIC_PAYL = 00 57 53 2D 50 41 59 4C        "\0WS-PAYL"
VERSION    = 01
WICK_ID    = SHA-256("wickset/v1/wickid" ‖ ALG_ID ‖ block 0)
NONCE ‖ CIPHERTEXT ‖ TAG = AES-GCM(key = S, random nonce,
                                   plaintext, additional data = HEADER)
TRAILER    = SHA-256(HEADER ‖ NONCE ‖ CIPHERTEXT ‖ TAG)
```

`S` is the wick's secret (SPEC.md §9), so the cipher is AES-256 for every
`B = 32` algorithm. The domain string is ASCII with no terminator; `ALG_ID` is
one byte; block 0 is `S ⊕ O[0]`.

**WICK_ID pairs a payload with its wick.** Neither extending (SPEC.md §7) nor
burning (§6) changes block 0, so `WICK_ID` is the same for a wick, every
extension of it and every partly burned copy, and computing it needs no
secret. Before burning, a reader checks, in order: the magic and version, the
trailer (else: corrupt), then that the payload's `WICK_ID` matches the wick's
(else: wrong pair). Only then does it burn. The GCM tag, checked after
burning, remains the only proof that `S` is right.

The whole payload is one GCM message, held in memory and bounded at about
64 GiB. That is by design: for bulk data, seal a small key file and encrypt
the data with it by ordinary means. Each `S` is fresh and encrypts one
message, so nonce reuse cannot occur.

## 4. Pairs

A wick and its payload are always two files, as they live different lives:
the wick grows with every extension and shrinks as it burns, while the
payload never changes once sealed. Keeping them apart means an extension or
a partly burned copy (§6) never rewrites or copies the payload, which may be
large, and lets the two travel by different routes.

wickset names a pair `FILE.wick` and `FILE.payload`, and opens it back into
`FILE`. Either file names the pair: given one, a reader finds the other
beside it by name, and checks that they pair (§3) before burning. To send a
pair as one file, use any archiver; wickset reads only the files themselves:

    tar cf notes.tar notes.txt.wick notes.txt.payload

## 5. Key

The wick's secret `S` is the payload's key. Whoever seals a wick may keep it
(`seal --key-out`), and whoever burns one may save it (`open --key-out`), to
decrypt the payload later without burning (`bypass`). Extension never changes
`S`, so a key outlives every extension of its wick.

```
key = "wickset-key-v1:" ‖ base64url(S)        unpadded, RFC 4648 §5
```

One line of ASCII, read and written as is; a reader ignores surrounding
whitespace. `S` is always drawn at random by seal and never supplied: no
operation encrypts under a caller's key. A key is the whole delay in one line,
so it belongs apart from the wick and payload; the CLI writes it with mode
0600 and never over an existing file (which may be another wick's key), reads
it from a file or standard input but never the command line, and warns when
its file is readable by others.

## 6. Partly burned wicks

A wick partly burned is itself a wick (SPEC.md §6), stored as a wick file
(§2) like any other. Saved by resumable opening (planned; not in the CLI
yet), one is named `FILE.wick.STEPS`, beside `FILE.wick`; `STEPS` is for
people, saying how far along it is, and a reader never relies on it: what a
file holds, and how much of it is left, come from its contents.
It pairs with the same payload, since block 0 and so `WICK_ID` are unchanged,
and it is recognized as a copy of a given wick by sharing its blocks up to
its last.
