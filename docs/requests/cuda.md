# Feature request: seal on NVIDIA GPUs (CUDA)

**Status:** open. Needs an NVIDIA GPU to develop and test on.

## Why

Sealing is where the cost is, and a GPU seals iterated SHA-256 (0x03/0x04)
about 40× faster than one core opens it (README, "Choosing parameters").
Today only Apple GPUs, through Metal, seal on the GPU; every other machine
falls back to its CPU workers.

## What exists

* The hashing is hashcat's (`internal/gpu/hashcat/`, vendored unmodified),
  written once for CUDA, HIP, Metal and OpenCL behind portable macros
  (`KERNEL_FQ`, `GLOBAL_AS`, …). Our entry points, `internal/gpu/kernel.cl`
  (Argon2id) and `sha256.cl` (iterated SHA-256), use the same macros.
* `internal/gpu` exposes one `Device`: `Open`, `Name`, `Memory`, `Batch` /
  `Hash` / `HashPartway` for Argon2id, `IterBatch` / `Iterate` for SHA-256.
  `internal/ops` uses only that API, with `stub.go` for builds without a GPU.
* The Metal host (`metal_darwin.go`, `.m`, `.h`) is the model for a new one:
  it compiles the expanded source at run time with the macros hashcat's own
  host passes, and runs init, one dispatch per segment and final for
  Argon2id, and dispatches of `iterDispatch` hashes for SHA-256.

## What to build

* A CUDA host, behind a build tag (e.g. `cuda`, with cgo), implementing the
  same `Device` API:
  * compile the expanded kernel source at run time with NVRTC, with
    hashcat's CUDA macros (`IS_CUDA`, `VENDOR_ID`, `CUDA_ARCH` from the
    device, …; see hashcat's `src/backend.c` at v8.0.0);
  * load and launch through the CUDA driver API; Argon2id's fill needs
    groups of exactly 32 threads (a warp), which CUDA always has;
  * `Memory` is the card's own memory, not the machine's: the default
    budget (`--gpu-memory`, 50%) then applies to VRAM.
* Selection: `gpu.Name()` reports the CUDA device where the build has CUDA
  and Metal is absent.

## Done when

* `TestMatchesXCrypto`, `TestRegisteredAlgs` and `TestIterate` pass on the
  CUDA device: every Argon2id and SHA-256 result equals x/crypto's and Go's.
* `TestSealWithGPU` seals on it and opens on the CPU.
* `wickset bench` on it reports its speed-up; a row goes in the README's
  table.

## Open questions

* Several GPUs: use the first, or let the user pick (`--gpu-device`)?
* Ship CUDA builds, or leave them to people who build from source? NVRTC and
  the driver come with the NVIDIA driver, not with Go.
