# Choosing parameters

What a step function buys is a high **seal:open ratio**: how many times
shorter sealing is than the delay it sets. Opening runs one step at a time on
one core; sealing runs as many as the hardware holds. Each family has a short
step and a long one, sized so their targets, ~8 h and ~2 w, come to about
2¹⁶–2¹⁷ steps (~3 MB of wick). That is also about what a GPU needs at once
to run SHA-256 at full speed. A step's length changes the wick's size, not
the ratio; the family and the hardware set that. `wickset bench` reports the
ratio for this machine as its speed-up.

| `--alg` | step | short or long | memory-hard |
|---|---|---|---|
| `0x01` | Argon2id, 128 MiB, 5 passes | short | yes |
| `0x02` | Argon2id, 128 MiB, 192 passes | long | yes |
| `0x03` | SHA-256, 2²⁴ times over | short | no |
| `0x04` | SHA-256, 2²⁹ times over | long | no |

Without `--alg`, a delay under a day uses the short step, longer the long
one: SHA-256 where there is a GPU, which seals it far faster, and Argon2id
without, keeping memory-hardness where that speed isn't on offer.

## Measurements

Measured on an Apple M5 (4 performance and 6 efficiency cores, 10 GPU cores,
32 GB, on mains power) with `wickset bench --csv`, on and off the GPU; every
number is a row of [benchmarks/scores.csv](../benchmarks/scores.csv).
Argon2id is from the libsodium build, which times a step directly; a step is
always timed as the fastest opener runs it (below).

| | step | all cores | ratio | GPU | ratio | 8 h / 2 w seal: cores | GPU |
|---|---|---|---|---|---|---|---|
| `0x01` | 0.23 s | 15.3 steps/s | 3.5 | 34.6 steps/s, 98 at once | 6.9 | 2.3 h | 70 min |
| `0x02` | 8.4 s | 0.52 steps/s | 4.3 | 1.42 steps/s, 98 at once | 11.4 | 3.2 d | 29 h |
| `0x03` | 0.36 s | 11.8 steps/s | 4.2 | 56.7 steps/s, 65,536 at once | 21.0 | 1.9 h | 23 min |
| `0x04` | 11.6 s | 0.39 steps/s | 4.5 | 1.78 steps/s, 65,536 at once | 21.2 | 3.1 d | 16 h |

A ratio is the sealing rate times the step: a seal takes the delay divided
by it. GitHub's runners, two shared vCPUs each, manage ratios of only 1.4 to
1.9 on their cores: sealing gains with every core and GPU thread, opening
with none.

The batch sizes are this machine's, not settings. Argon2id batches are as
many steps as fit the GPU memory budget (`--gpu-memory`, half by default).
SHA-256 batches are found on first use by doubling them until throughput
stops growing. A run goes to the GPU only where it would finish sooner than
the CPU; a seal of a few steps stays on the CPU.

## The two families

**Argon2id** (`0x01`, `0x02`) is memory-hard: a step waits on memory, which
narrows what faster hardware gains. It is also what holds GPUs back: its
mixing uses 64-bit multiplies, which GPUs do slowly. Every memory size from 1
to 64 MiB topped out at about 3× all cores on the GPU, and 1 GiB at 1×.
128 MiB costs little against 64 MiB and is larger than the biggest
last-level caches a single core sees (96 MB on AMD's X3D parts), so a step
stays in DRAM.

**Iterated SHA-256** (`0x03`, `0x04`) is plain sequential hashing: 32-bit
arithmetic, 32 bytes of state, so a GPU runs a hundred thousand steps at
once. One GPU thread is ~125× slower than a CPU core, so a GPU does not help
an opener. What it gives up is memory-hardness: a dedicated chip for one
fast step could burn sooner, plausibly by a few times. CPUs hash SHA-256 in
hardware (ARMv8 SHA2, x86 SHA-NI), which keeps an opener's CPU close to the
best there is.

## A delay is timed against the fastest opener

The sealer and the opener are seldom the same person, and an opener can
bring a faster implementation. So seal times a step as the fastest known one
runs it: iterated SHA-256 at this core's full compression rate, which a
tight loop reaches and ours nearly does; Argon2id at libsodium's speed. An
opener using wickset itself takes a little longer than the delay.

A build with libsodium (`-tags libsodium`, as the release binaries are)
runs Argon2id on it and times it directly. A build without it divides its
own time by **×1.72, the largest lead libsodium has been measured to have**
over x/crypto:

| machine | libsodium | `0x01` | `0x02` |
|---|---|---|---|
| Apple M5 | 1.0.22 | ×1.34 | ×1.53 |
| AMD EPYC 7763 (2 vCPU) | 1.0.18 | ×1.34 | **×1.72** |
| GitHub's Arm runner (2 vCPU) | 1.0.18 | ×1.23 | ×1.34 |

The lead varies by machine, by libsodium version and by step (the long
step's is the larger everywhere), so any single figure is wrong somewhere.
The two ways of being wrong are not alike: a lead set too high makes a delay
longer than it need be, which costs the sealer some patience; one set too
low lets an opener with libsodium in early, which defeats the delay. So the
largest measured is taken. It overstates the short step's delay by a
quarter on most machines; where that matters, use a build with libsodium.
As more machines are benched, the figure is revisited.

## Delegating a seal hands over the key

Sealing on faster hardware you don't control, a cloud GPU or an ASIC farm,
hands over the key. A helper who computed `H` for the steps, and later sees
the wick, recovers every value in it and burns it in about one step. The
steps you compute yourself protect you only as far as their longest unbroken
run. Seal on hardware you control.
