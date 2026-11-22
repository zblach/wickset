# wickset

**Encrypt a file so it can be opened only after a delay. A wick is built in
parallel, but burns only in serial.**

A wick is a run of hash steps. The sealer picks every step's input at random,
so all steps run at once on every core. The opener must feed each step's
output into the next, one at a time, burning the wick down to its secret.

```
seal   I[0]  I[1]  …  I[N]      random inputs, hashed side by side
         H     H   …    H       published: each output XOR the previous input, plus I[N]

burn   I[N] ─H→ I[N-1] ─H→ … ─H→ I[0] ─H→ S    one step at a time
```

`S` is the key to the encrypted file.

* **Two kinds of step:** memory-hard Argon2id, or iterated SHA-256 that seals
  ~40× faster than it opens on a GPU.
* **Extensible without the secret:** anyone holding a wick can add steps.
* **Hardware-relative:** a wick is a step count, not a date. Faster machines
  burn it sooner.

[SPEC.md](SPEC.md) defines the format; [CONTAINER.md](CONTAINER.md) the files.

## Quick start

    go install ./cmd/wickset

    wickset seal -d 8h notes.txt         # → notes.txt.wick, notes.txt.payload
    wickset info notes.txt.wick          # what it is; are its files intact
    wickset open notes.txt.wick          # 8h later, on this machine: → notes.txt
    wickset tui                          # all of it, interactively

## Delay and algorithm

`-d` takes a time span: `90s`, `30min`, `8h`, `3d`, `2w`, `6M`, `1y`, or
`"1w 3d"` (`m` is minutes, `M` months). Seal times one step on this machine
and turns the delay into steps. `-n N` with `--alg` gives an exact count
(`N+1` steps).

| `--alg` | step | short or long | memory-hard |
|---|---|---|---|
| `0x01` | Argon2id, 128 MiB, 5 passes | short, ~0.3 s | yes |
| `0x02` | Argon2id, 128 MiB, 192 passes | long, ~11 s | yes |
| `0x03` | SHA-256, 2²³ times over | short, ~0.3 s | no |
| `0x04` | SHA-256, 2²⁸ times over | long, ~11 s | no |

Without `--alg`, a delay under a day uses the short step, longer the long
one: SHA-256 with `--gpu`, which seals it far faster, and Argon2id without,
keeping memory-hardness where that speed isn't on offer. `wickset bench`
times this machine.

**Sealing costs as much compute as the delay**, split across the workers.
Each Argon2id worker holds a step's memory, so `--workers` bounds memory too.
Never seal on someone else's machine: whoever computes the steps learns the
key (see below).

**`wickset --gpu …`** seals and extends on the GPU (macOS, Metal), in
batches sized to the GPU at hand. Opening stays on the CPU, which runs a
single step faster than a GPU; a delay is set by the faster of the two, so it
holds against either. The CPU checks one step of every batch, and a mismatch
stops the seal.

## Choosing parameters

What a step function buys is a high **seal:open ratio**: how many times
shorter sealing is than the delay it sets. Opening runs one step at a time on
one core; sealing runs as many as the hardware holds. Each family has a short
step and a long one, sized so their targets, ~8 h and ~2 w, come to about
2¹⁶–2¹⁷ steps (~3 MB of wick). That is also about what a GPU needs at once
to run SHA-256 at full speed. A step's length changes the wick's size, not
the ratio; the family and the hardware set that. `wickset bench` reports the
ratio for this machine as its speed-up.

Measured on an Apple M5 (4 performance and 6 efficiency cores, 10 GPU cores,
32 GB, on mains power), with `wickset bench` and `--gpu bench`:

| | step | all cores | ratio | GPU | ratio | 8 h / 2 w seal, GPU |
|---|---|---|---|---|---|---|
| `0x01` | 0.30 s | 15.7 steps/s | 4.7 | 41 steps/s, 98 at once | 12 | 40 min |
| `0x02` | 11.4 s | 0.4 steps/s | 4.6 | 1.5 steps/s, 98 at once | 17 | 20 h |
| `0x03` | 0.33 s | 19.0 steps/s | 6.3 | 129 steps/s, ~262 k at once | 43 | 11 min |
| `0x04` | 10.9 s | 0.6 steps/s | 6.6 | 3.9 steps/s, ~131 k at once | 43 | 8 h |

The batch sizes are this machine's, not settings. Argon2id batches are as
many steps as fit half the memory the GPU recommends. SHA-256 batches are
found on first use by doubling them until throughput stops growing.

**Argon2id** (`0x01`, `0x02`) is memory-hard: a step waits on memory, which
narrows what faster hardware gains. It is also what holds GPUs back: its
mixing uses 64-bit multiplies, which GPUs do slowly. Every memory size from 1
to 64 MiB topped out at about 3× all cores on the GPU, and 1 GiB (an earlier
`0x02`) at 1×. 128 MiB costs little against 64 MiB and is larger than
the biggest last-level caches a single core sees (96 MB on AMD's X3D parts),
so a step stays in DRAM.

**Iterated SHA-256** (`0x03`, `0x04`) is plain sequential hashing: 32-bit
arithmetic, 32 bytes of state, so a GPU runs a hundred thousand steps at
once. One GPU thread is ~125× slower than a CPU core, so a GPU does not help
an opener. What it gives up is memory-hardness: a dedicated chip for one
fast step could burn sooner, plausibly by a few times. CPUs hash SHA-256
in hardware (ARMv8 SHA2, x86 SHA-NI), which keeps an opener's CPU close to
the best there is. The timing is through Go's `crypto/sha256`, call overhead
included; a tighter loop burns a little sooner.

**Delegating a seal** to faster hardware, a cloud GPU or an ASIC farm, hands
over the key. A helper who computed `H` for the steps, and later sees the
wick, recovers every value in it and burns it in about one step. The steps
you compute yourself protect you only as far as their longest unbroken run.
Seal on hardware you control.

## CLI

    wickset seal -d 2w --archive notes.txt    # → notes.txt.wick.tar
    wickset seal -d 8h --raw notes.txt        # bare SPEC.md wick
    wickset --gpu seal -d 2w notes.txt        # on the GPU
    wickset extend -d 1w notes.txt.wick       # in place; no secret needed
    wickset seal -d 8h --key-out ~/n.key notes.txt
    wickset bypass --key ~/n.key notes.txt.payload   # opens at once

`wickset COMMAND --help` lists the flags. Exit status: 0 ok, 1 failure,
2 bad usage.

## TUI

`wickset tui [FILE]` offers every command as a form. Tab completes paths,
`?` explains fields. The title shows whether the GPU is on (`--gpu` at start).
A run's bar shows steps finished, in progress and pending.

## Files and keys

Seal writes `FILE.wick` and `FILE.payload`, or `FILE.wick.tar` with
`--archive`. Open writes `FILE`. Damage and mismatched pairs are refused
before any burning. Nothing existing is ever replaced.

A holder can extend a wick before passing it on; the unextended copy is a
shortcut to keep private. The key (`--key-out`) opens the file at once
however far the wick is extended: keep it apart from the wick.

## Library

    raw, payload, key, err := wickset.Seal(ctx, pt, wickset.SealOpts{Alg: alg.SHA256Short, N: 99})
    pt, key, err := wickset.Open(ctx, raw, payload, report)   // report: wick.Report, or nil
    ext, err := wick.Extend(ctx, raw, 50, wick.Opts{})
    pt, err = format.OpenPayload(key, payload)   // with a saved key

`S` is drawn only by `wick.New`, from `crypto/rand`. Cancelling stops every
step within a quarter pass, or a million hashes.

Argon2id is vendored twice, pinned by tested checksums: x/crypto's with a
context added (`internal/argon2`), and hashcat's GPU kernels unmodified
(`internal/gpu`, Argon2id and SHA-256). They are tested against x/crypto and
Go's SHA-256.

## Build and test

    go test -short ./...                   # skips the slow long-step vectors
    go test -tags wickset_testalgs ./...   # adds CLI/TUI end-to-end tests

The tag adds cheap test algorithms: never ship a binary built with it. GPU
tests run natively on a Mac. To read every TUI screen after a change,
`go test ./internal/tui -run Screens -args -screens DIR` writes them to DIR.

## Layout

    wickset (root)      Seal, Open
    alg                 step functions (SPEC.md §3)
    wick                the wick: build, extend, burn
    format              wick and payload files (CONTAINER.md)
    internal/argon2     Argon2id (CPU), vendored, cancellable
    internal/gpu        Argon2id and iterated SHA-256 (GPU), hashcat's on Metal
    internal/store      on-disk forms and naming
    internal/ops        the commands, for any front end
    internal/cli        command line
    internal/tui        terminal UI
    cmd/wickset         main, end-to-end tests
