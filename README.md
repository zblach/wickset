# chainlock

**Encrypt something so that it can be opened only after a delay: hours,
weeks, or longer. A chainlock is built in parallel, but can be solved only in
serial.**

The lock is a chain of hash steps. To build it, the sealer picks every step's
input at random, so the steps are independent and run at once, on every core.
To solve it, each step's input is the previous step's output, so the solver
must take them one after another, on one core, however many cores it has. The
work is the same either way; only the sealer can spread it out.

```
seal   I[0]  I[1]  I[2]  …  I[N]       random inputs, hashed side by side
         │     │     │        │         across all cores
         H     H     H   …    H
                                        published: each output XOR the
                                        previous input, plus I[N]

solve  I[N] ─H→ I[N-1] ─H→ … ─H→ I[0] ─H→ S    one step at a time
```

The secret `S` at the end is the key to the encrypted file. On a 10-core
machine a two-week lock takes a day and a half or more to seal (the cores
share memory bandwidth) and two weeks to solve.

* **Memory-hard steps.** Each step is Argon2id over 256 MiB or 1 GiB. A step
  is bound by memory speed, so special hardware gains far less on it than on
  an ordinary hash.
* **Extensible without the secret.** Anyone holding a lock can add steps
  before passing it on, and those downstream must solve the longer chain.
* **The delay is hardware-relative.** A lock is a number of steps, not a
  date. Faster machines open it sooner: choose it for the fastest machine
  that might try.

The byte-level format is in [SPEC.md](SPEC.md), which is the authority. How
locks and encrypted files are stored on disk is in [CONTAINER.md](CONTAINER.md).

## Quick start

    go install ./cmd/chainlock             # or: go run ./cmd/chainlock …

    chainlock seal -d 8h notes.txt         # → notes.txt.lock, notes.txt.payload
    chainlock info notes.txt.lock          # what it is, and whether its files are intact
    chainlock open notes.txt.lock          # 8h later (on this machine): → notes.txt
    chainlock tui                          # all of the above, interactively

## Choosing a delay

`--delay` (`-d`) takes a time span: `90s`, `30min`, `8h`, `3d`, `2w`, `6M`,
`1y`, or several, `"1w 3d"` or `"2 weeks"`. Lowercase `m` is minutes and
capital `M` months; a month is 30.44 days and a year 365.25. (This is
systemd's time-span syntax, systemd.time(7), except that a number needs a
unit.) Seal times one step on this machine and converts the
delay to a step count, so the delay holds on machines as fast as this one.
For a known count instead, give `-n N` (the solver takes `N+1` steps) with
`--alg`.

There are two algorithms (SPEC.md §3). `--delay` picks one if `--alg` is
not given: `0x01` below a day, `0x02` from a day up.

| `--alg` | name | memory | passes | step today | two-week lock |
|---|---|---|---|---|---|
| `0x01` | `argon2id-m256M-t3-p1` | 256 MiB | 3 | ~0.4 s | 3.4 M steps, 108 MB |
| `0x02` | `argon2id-m1G-t30-p1` | 1 GiB | 30 | ~16 s | 76 k steps, 2.4 MB |

The step times are one laptop core's, in 2026; `chainlock bench --alg ID`
measures this machine's. `0x02`'s step is about 40× `0x01`'s, so a long lock
is 40× smaller. Sealing takes the same time with either.

**Sealing costs as much CPU as the delay**, divided only by the workers: a 12h
lock takes 3h or more to make on 4 cores. Seal by delay states its estimate
before it starts. Each worker holds the algorithm's memory, so `--workers`
also bounds memory. Containers often get fewer cores than their host (Docker
Desktop's default is 4): seal where the cores are. Never hand the sealing to
someone else's machines: whoever computes the steps learns the key.

## CLI

    chainlock seal -d 8h notes.txt              # → notes.txt.lock, notes.txt.payload
    chainlock seal -n 99 --alg 1 notes.txt      # exactly 100 steps of 0x01
    chainlock seal -d 2w --archive notes.txt    # → notes.txt.chainlock.tar
    chainlock seal -d 8h --raw notes.txt        # bare SPEC.md object, no digest
    chainlock extend -d 1w notes.txt.lock       # in place; no secret needed
    chainlock open notes.txt.lock               # → notes.txt
    chainlock info notes.txt.lock               # checks the pair, without solving
    chainlock bench --alg 2                     # this machine's step time

    chainlock seal -d 8h --key-out ~/notes.key notes.txt   # keep a shortcut
    chainlock bypass --key ~/notes.key notes.txt.payload   # → notes.txt, at once
    chainlock open --key-out ~/notes.key notes.txt.lock    # save it after solving

`chainlock COMMAND --help` lists every flag. Exit status is 0 on success, 1
on failure and 2 on a bad invocation. Progress goes to standard error: on a
terminal, one line kept current (count, the step under way or the workers,
elapsed, estimate); otherwise a line per finished step.

## TUI

`chainlock tui [FILE]` offers every command as a form, each starting from
FILE if given (the menu offers first the command that suits it): file names
complete on tab,
`?` explains the fields, and a run shows an overall bar and a bar per worker
(or, when solving, for the step in progress), with pace and estimate. Cancel
asks first, and stops every worker mid-step; cancelled work is lost, as
nothing resumes it. The TUI never shows a key and takes keys only as file
paths: standard input and output belong to the interface.

## Files

Seal writes `FILE.lock` and `FILE.payload` (the encrypted file), or with
`--archive` both in one tar, `FILE.chainlock.tar`, which `tar xf` unpacks into
the pair. Open writes `FILE`. Every command detects a lock's form from its
content, and `extend` writes it back in the same form. `--lock`, `--payload`
and `--out` choose other names.

A lock file is a short header with a SHA-256 of the SPEC.md object, then the
object. An encrypted file is AES-GCM under `S`, with a header naming its lock
and a SHA-256 trailer. Before any solving, `open` refuses a damaged lock, a
damaged encrypted file, and a pair that do not belong together. The digests
catch accidents, not attackers: authenticity is a signed manifest's job
(SPEC.md §10).

**Nothing is replaced by surprise.** Seal refuses if its outputs exist, since
they may hold an earlier lock; a key file is never replaced; `extend --out`
must name a new file; and open refuses if its default output exists. Each
refusal comes before any solving or sealing.

The file is encrypted in one piece, in memory. For large data, lock a small
key file and encrypt the data with that key by ordinary means (e.g. `age`).

## Shortcuts: extension and keys

Extension is how a holder makes a lock harder for those downstream: keep the
unextended copy private and hand on only extended ones. Whoever holds a
shorter copy can still open it in its original steps, so that copy is the
shortcut to protect. Extending in place does not scrub it from disk,
snapshots, backups or synced folders.

The key (`--key-out`) is the ultimate shortcut: the lock's secret, which opens
the encrypted file at once with `bypass`, however far the lock is extended.
It is never generated from or accepted as user input, only saved and read back
(CONTAINER.md §5), and never given on the command line. Keep it apart from
the lock.

## Library

    lock, payload, key, err := chainlock.Seal(ctx, plaintext, chainlock.SealOpts{Alg: alg.Argon2id256M, N: 99})
    pt, key, err := chainlock.Open(ctx, lock, payload, progress)

    file := format.EncodeLockFile(lock)            // what the CLI writes as FILE.lock
    lock, _, err = format.DecodeLock(file)         // lock file or raw object; verifies the digest
    o, err := chain.Parse(lock)
    err = format.CheckPayload(o, payload)          // pre-flight, no solving
    pt, err = format.OpenPayload(key, payload)     // with a saved key: no lock, no solving
    ext, err := chain.Extend(ctx, lock, 50, chain.Opts{})

`chainlock` is the front door, `Seal` and `Open`; under it, `alg` is the
registry of step functions, `chain` the lock object (built in parallel by
`New` and `Extend`, solved in serial by `Solve`), and `format` the lock and
payload files. `S` is only ever drawn by `chain.New`, from `crypto/rand`:
nothing takes a caller's secret or randomness. A `chain.Key` prints as a
redaction under every `fmt` verb; `Encode` and `ParseKey` are its text form.

Cancelling the context returns at once (`alg.Eval`): the steps in flight
finish in the background and are dropped, holding their cores and memory
for up to one more step. No step function needs to know about cancelling,
so Argon2id is x/crypto's own. `chain.Opts` sets the workers and the
callbacks: `Progress` reports finished steps, and `Activity` each worker
starting one, which shows a run under way before the first step of many
seconds ends.

## Build and test

The devcontainer (`.devcontainer/`) has Go 1.27; the module needs 1.26.

    go test -short ./...                     # skips the 0x02 vector
    go test ./...                            # adds it: ~16 s and 1 GiB more
    go test -tags chainlock_testalgs ./...   # adds the CLI and TUI end-to-end tests

The `chainlock_testalgs` tag registers cheap steps at the private-use ids
`0xFE` and `0xFF` (SPEC.md §3), so the end-to-end tests run the real CLI and
TUI through seal, extend and open in milliseconds. Their locks have no real
delay: never ship a binary built with the tag. It warns on every run. Default
builds reject all of `0xF0–0xFF`.

The TUI's screens are drawn from plain values, so any state can be drawn
without running anything. `internal/tui/testdata/*.txt` holds them as text;
after a deliberate change, `go test ./internal/tui -run Rendered -args -update`
redraws them.

## Layout

    chainlock (root)    Seal and Open: the library's front door
    alg                 the step functions (SPEC.md §3)
    chain               the lock object: build, extend, solve; its Key
    format              the lock file and the payload file (CONTAINER.md)
    internal/store      on-disk forms and naming (CONTAINER.md)
    internal/ops        the commands, on files, for any front end; reports through callbacks
    internal/cli        the command line (kong) over ops
    internal/tui        the interactive interface (Bubble Tea) over ops
    cmd/chainlock       main, and the end-to-end tests

Both front ends run the same `ops`, so they write the same files, refuse the
same things before solving, and report the same lines.
