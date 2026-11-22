# chainlock

**Encrypt a file so it can be opened only after a delay. A chainlock is
built in parallel, but can be solved only in serial.**

The lock is a chain of hash steps. The sealer picks every step's input at
random, so all steps run at once on every core. The solver must feed each
step's output into the next, one at a time.

```
seal   I[0]  I[1]  …  I[N]      random inputs, hashed side by side
         H     H   …    H       published: each output XOR the previous input, plus I[N]

solve  I[N] ─H→ I[N-1] ─H→ … ─H→ I[0] ─H→ S    one step at a time
```

`S` is the key to the encrypted file.

* **Two kinds of step:** memory-hard Argon2id, or SHA-256 chains that seal
  ~40× faster than they open on a GPU.
* **Extensible without the secret:** anyone holding a lock can add steps.
* **Hardware-relative:** a lock is a step count, not a date. Faster machines
  open it sooner.

[SPEC.md](SPEC.md) defines the format; [CONTAINER.md](CONTAINER.md) the files.

## Quick start

    go install ./cmd/chainlock

    chainlock seal -d 8h notes.txt         # → notes.txt.lock, notes.txt.payload
    chainlock info notes.txt.lock          # what it is; are its files intact
    chainlock open notes.txt.lock          # 8h later, on this machine: → notes.txt
    chainlock tui                          # all of it, interactively

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
keeping memory-hardness where that speed isn't on offer. `chainlock bench`
times this machine.

**Sealing costs as much compute as the delay**, split across the workers.
Each Argon2id worker holds a step's memory, so `--workers` bounds memory too.
Never seal on someone else's machine: whoever computes the steps learns the
key (see below).

**`chainlock --gpu …`** seals and extends on the GPU (macOS, Metal), in
batches sized to the GPU at hand. Opening stays on the CPU, which runs a
single step faster than a GPU; a delay is set by the faster of the two, so it
holds against either. The CPU checks one step of every batch, and a mismatch
stops the seal.

## Choosing parameters

What a step function buys is a high **seal:open ratio**: how many times
shorter sealing is than the delay it sets. Opening runs one step at a time on
one core; sealing runs as many as the hardware holds. Each family has a short
step and a long one, sized so their targets, ~8 h and ~2 w, come to about
2¹⁶–2¹⁷ steps (~3 MB of lock). That is also about what a GPU needs at once
to run SHA-256 at full speed. A step's length changes the lock's size, not
the ratio; the family and the hardware set that.

Measured on an Apple M5 (4 performance and 6 efficiency cores, 10 GPU cores,
32 GB, on mains power), with `chainlock bench` and `--gpu bench`:

| | step | all cores | ratio | GPU | ratio | 8 h / 2 w seal, GPU |
|---|---|---|---|---|---|---|
| `0x01` | 0.30 s | 15.7 steps/s | 4.7 | 41 steps/s, 98 at once | 12 | 40 min |
| `0x02` | 11.4 s | 0.4 steps/s | 4.6 | 1.5 steps/s, 98 at once | 17 | 20 h |
| `0x03` | 0.33 s | 19.0 steps/s | 6.3 | 129 steps/s, ~262 k at once | 43 | 11 min |
| `0x04` | 10.9 s | 0.6 steps/s | 6.6 | 3.9 steps/s, ~131 k at once | 43 | 8 h |

The batch sizes are this machine's, not settings. Argon2id batches are as
many steps as fit half the memory the GPU recommends. SHA-256 batches are
found on first use by doubling the chains until throughput stops growing.

**Argon2id** (`0x01`, `0x02`) is memory-hard: a step waits on memory, which
narrows what faster hardware gains. It is also what holds GPUs back: its
mixing uses 64-bit multiplies, which GPUs do slowly. Every memory size from 1
to 64 MiB topped out at about 3× all cores on the GPU, and 1 GiB (an earlier
`0x02`) at 1×. 128 MiB costs little against 64 MiB and is larger than
the biggest last-level caches a single core sees (96 MB on AMD's X3D parts),
so a step stays in DRAM.

**SHA-256 chains** (`0x03`, `0x04`) are plain sequential hashing: 32-bit
arithmetic, 32 bytes of state, so a GPU runs a hundred thousand chains at
once. One GPU thread is ~125× slower than a CPU core, so a GPU does not help
an opener. What they give up is memory-hardness: a dedicated chip for one
fast chain could open sooner, plausibly by a few times. CPUs hash SHA-256
in hardware (ARMv8 SHA2, x86 SHA-NI), which keeps an opener's CPU close to
the best there is. The timing is through Go's `crypto/sha256`, call overhead
included; a tighter loop opens a little sooner.

**Delegating a seal** to faster hardware, a cloud GPU or an ASIC farm, hands
over the key. A helper who computed `H` for the steps, and later sees the
lock, recovers every chain value from it and opens it in about one step. The
steps you compute yourself protect you only as far as their longest unbroken
run. Seal on hardware you control.

## CLI

    chainlock seal -d 2w --archive notes.txt    # → notes.txt.chainlock.tar
    chainlock seal -d 8h --raw notes.txt        # bare SPEC.md object
    chainlock --gpu seal -d 2w notes.txt        # on the GPU
    chainlock extend -d 1w notes.txt.lock       # in place; no secret needed
    chainlock seal -d 8h --key-out ~/n.key notes.txt
    chainlock bypass --key ~/n.key notes.txt.payload   # opens at once

`chainlock COMMAND --help` lists the flags. Exit status: 0 ok, 1 failure,
2 bad usage.

## TUI

`chainlock tui [FILE]` offers every command as a form. Tab completes paths,
`?` explains fields. The title shows whether the GPU is on (`--gpu` at start).
A seal's bar shows steps finished, in progress and pending.

## Files and keys

Seal writes `FILE.lock` and `FILE.payload`, or `FILE.chainlock.tar` with
`--archive`. Open writes `FILE`. Damage and mismatched pairs are refused
before any solving. Nothing existing is ever replaced.

A holder can extend a lock before passing it on; the unextended copy is a
shortcut to keep private. The key (`--key-out`) opens the file at once
however far the lock is extended: keep it apart from the lock.

## Library

    lock, payload, key, err := chainlock.Seal(ctx, pt, chainlock.SealOpts{Alg: alg.SHA256Short, N: 99})
    pt, key, err := chainlock.Open(ctx, lock, payload, report)   // report: chain.Report, or nil
    ext, err := chain.Extend(ctx, lock, 50, chain.Opts{})
    pt, err = format.OpenPayload(key, payload)   // with a saved key

`S` is drawn only by `chain.New`, from `crypto/rand`. Cancelling stops every
step within a quarter pass.

Argon2id is vendored twice, pinned by tested checksums: x/crypto's with a
context added (`internal/argon2`), and hashcat's GPU kernels unmodified
(`internal/gpu`, Argon2id and SHA-256). They are tested against x/crypto and
Go's SHA-256.

## Build and test

    go test -short ./...                     # skips the slow long-step vectors
    go test -tags chainlock_testalgs ./...   # adds CLI/TUI end-to-end tests

The tag adds cheap test algorithms: never ship a binary built with it. GPU
tests run natively on a Mac. To read every TUI screen after a change,
`go test ./internal/tui -run Screens -args -screens DIR` writes them to DIR.

## Layout

    chainlock (root)    Seal, Open
    alg                 step functions (SPEC.md §3)
    chain               the lock object: build, extend, solve
    format              lock and payload files (CONTAINER.md)
    internal/argon2     Argon2id (CPU), vendored, cancellable
    internal/gpu        Argon2id and SHA-256 chains (GPU), hashcat's on Metal
    internal/store      on-disk forms and naming
    internal/ops        the commands, for any front end
    internal/cli        command line
    internal/tui        terminal UI
    cmd/chainlock       main, end-to-end tests
