# wickset

**Encrypt a file so that it can be opened only after a delay, with no one
holding the key in the meantime.**

    wickset seal -d 2w notes.txt      # → notes.txt.wick, notes.txt.payload
    wickset open notes.txt.wick       # two weeks of computing later → notes.txt

## How it works

The file itself is encrypted with ordinary symmetric cryptography: AES-256-GCM
under a random 32-byte key `S`. What is unusual is where the key goes. It is
hidden at the end of a **wick**, a chain of hash steps, and the only way to
recover it is to compute every step, in order.

```
seal   I[0]  I[1]  …  I[N]      random inputs, all hashed at once
         H     H   …    H       published: each output XOR the previous input, plus I[N]

burn   I[N] ─H→ I[N-1] ─H→ … ─H→ I[0] ─H→ S    one step at a time
```

The asymmetry is in the computing, not in the keys. The sealer picks every
step's input, so every step can be computed side by side, on every core or
thousands of GPU threads at once. The opener must feed each step's output
into the next, so no amount of extra hardware helps: opening takes as long
as the steps take on one fast core. Sealing a two-week wick on a GPU takes
hours.

* **No trusted party.** Nobody holds the key during the delay; the delay is
  the work itself.
* **Extensible without the key.** Anyone holding a wick can add steps,
  making it longer, before passing it on.
* **Hardware-relative.** A wick is a count of steps, not a date. Seal times a
  step against the fastest known implementation, but faster hardware burns
  sooner, and a dedicated chip could burn much sooner. Treat a delay as a
  floor on effort, not a schedule.

[SPEC.md](SPEC.md) defines the wick; [CONTAINER.md](CONTAINER.md) the files.

## Uses

* **Vulnerability disclosure.** Publish the write-up as a wick on the day
  you report it. The vendor can see it exists and knows it opens itself on
  schedule, with or without you.
* **Insurance files.** Material that should come out eventually even if its
  holder can't release it, without trusting anyone to hold a key.
* **Sealed bids and predictions.** Commit to something now, publicly, in a
  form that opens only after the deadline.
* **Time capsules and self-binding.** Lock away a message, or a password you
  don't want to be able to reach until later.
* **Puzzles and games**, where the delay is the point.

## Using it

[Releases](https://github.com/zblach/wickset/releases) have binaries for
macOS on Apple silicon (GPU sealing), Linux on x86_64 and arm64, and Windows
(CPU only), each with libsodium built in, and `SHA256SUMS`. On macOS,
`xattr -d com.apple.quarantine wickset` lets an unsigned download run. Or
build it: `go install ./cmd/wickset`.

    wickset seal -d 8h notes.txt         # 8 hours, on this kind of machine
    wickset info notes.txt.payload       # what it is; do its files pair and check out
    wickset open notes.txt.payload       # either file names the pair
    wickset extend -d 1w notes.txt.wick  # a week longer; no key needed
    wickset bench                        # what a step takes here
    wickset tui                          # all of the above, interactively

`-d` takes `90s`, `30min`, `8h`, `3d`, `2w`, `6M` or `"1w 3d"`. Sealing uses
the GPU where there is one (Metal on macOS) and it would finish sooner;
`--cpu` keeps to the CPU. `--key-out` saves the key, which opens the file at
once with `wickset bypass`: keep it apart from the wick.

A wick and its payload are two files, `FILE.wick` and `FILE.payload`, since
the wick changes when extended and the payload never does. To send them as
one, archive them: `tar cf notes.tar notes.txt.wick notes.txt.payload`.
Damaged or mismatched files are refused before any burning, and nothing
existing is ever overwritten.

`wickset tui [FILE]` offers every command as a form, starting on open for a
wick or payload, seal for any other file, and bench with none. `?` explains
each field. `wickset completion zsh` (or `bash`, `fish`) prints shell
completion.

[examples/](examples/) holds a sample wick for each algorithm, each 10 to 15
seconds to burn. [docs/parameters.md](docs/parameters.md) explains the four
step functions, how they were chosen, and why you should never seal on
someone else's hardware.

## Benchmarking

How long a wick takes depends on the opener's hardware, so step times from
many machines say more than any one. [benchmarks/scores.csv](benchmarks/scores.csv)
collects them; [benchmarks/README.md](benchmarks/README.md) explains the
columns. To add yours, on an otherwise idle machine on mains power:

    wickset bench --submit

It benches every algorithm, on the CPU and on the GPU if wickset can use
one, which takes several minutes. It then prints the rows and a link to
GitHub's new-file page with them filled in. Following the link makes you a
fork and opens the pull request; nothing is sent unless you do.

## Library

    raw, payload, key, err := wickset.Seal(ctx, pt, wickset.SealOpts{Alg: alg.SHA256Short, N: 99})
    pt, key, err := wickset.Open(ctx, raw, payload, nil)
    ext, err := wick.Extend(ctx, raw, 50, wick.Opts{})

## Building

    go build ./cmd/wickset                    # cgo: the GPU where there is one
    CGO_ENABLED=0 go build ./cmd/wickset      # pure Go, CPU only
    go build -tags libsodium ./cmd/wickset    # Argon2id on libsodium (installed)
    CGO_LDFLAGS=/opt/homebrew/lib/libsodium.a \
      go build -tags "libsodium libsodium_static" ./cmd/wickset   # libsodium built in, as releases are

    go test -short ./...
    go test -tags wickset_testalgs ./...      # adds end-to-end tests; never ship this build

All builds open the same wicks. Releases follow semantic versioning, from
git tags; `wickset --version` names the release and what the build can do
(GPU, libsodium). The file format is versioned separately and changes only
when the bytes on disk do. Vendored code (x/crypto's Argon2id, hashcat's GPU
kernels, Go's SHA-256 assembly) is pinned by tested checksums.

0BSD licensed; see [LICENSE](LICENSE).
