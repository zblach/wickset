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

* **Memory-hard steps:** Argon2id over 256 MiB or 1 GiB.
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

| `--alg` | memory | passes | step (one core) | two-week lock |
|---|---|---|---|---|
| `0x01` | 256 MiB | 3 | ~0.4 s | 3.4 M steps, 108 MB |
| `0x02` | 1 GiB | 30 | ~16 s | 76 k steps, 2.4 MB |

Without `--alg`, a delay under a day uses `0x01`, longer `0x02`.
`chainlock bench` times this machine.

**Sealing costs as much compute as the delay**, split across the workers.
Each worker holds a step's memory, so `--workers` bounds memory too. Never
seal on someone else's machine: whoever computes the steps learns the key.

**`chainlock --gpu …`** seals and extends on the GPU (macOS, Metal), in
batches: on an M5, 0x01 about twice as fast as all its cores. Opening
stays on the CPU, which runs a single step faster than a GPU; a delay is
set by the faster of the two, so it holds against either. The CPU checks one
step of every batch, and a mismatch stops the seal.

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

    lock, payload, key, err := chainlock.Seal(ctx, pt, chainlock.SealOpts{Alg: alg.Argon2id256M, N: 99})
    pt, key, err := chainlock.Open(ctx, lock, payload, progress)
    ext, err := chain.Extend(ctx, lock, 50, chain.Opts{})
    pt, err = format.OpenPayload(key, payload)   // with a saved key

`S` is drawn only by `chain.New`, from `crypto/rand`. Cancelling stops every
step within a quarter pass.

Argon2id is vendored twice, pinned by tested checksums: x/crypto's with a
context added (`internal/argon2`), and hashcat's GPU kernel unmodified
(`internal/argon2gpu`). Both are tested against x/crypto.

## Build and test

    go test -short ./...                     # skips the slow 0x02 vector
    go test -tags chainlock_testalgs ./...   # adds CLI/TUI end-to-end tests

The tag adds cheap test algorithms: never ship a binary built with it. GPU
tests run natively on a Mac. After a deliberate TUI change,
`go test ./internal/tui -run Rendered -args -update` redraws the stored screens.

## Layout

    chainlock (root)    Seal, Open
    alg                 step functions (SPEC.md §3)
    chain               the lock object: build, extend, solve
    format              lock and payload files (CONTAINER.md)
    internal/argon2     Argon2id (CPU), vendored, cancellable
    internal/argon2gpu  Argon2id (GPU), hashcat's kernel on Metal
    internal/store      on-disk forms and naming
    internal/ops        the commands, for any front end
    internal/cli        command line
    internal/tui        terminal UI
    cmd/chainlock       main, end-to-end tests
