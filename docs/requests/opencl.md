# Feature request: seal on any GPU (OpenCL)

**Status:** open. Testable on any OpenCL device, including the Linux
devcontainer with a CPU OpenCL runtime (pocl) for correctness.

## Why

One OpenCL host would let NVIDIA, AMD and Intel GPUs on Linux and Windows
seal on the GPU, where today they fall back to CPU workers. It covers more
hardware than CUDA alone (docs/requests/cuda.md), and can be tested without
an NVIDIA card. Sealing iterated SHA-256 on a GPU is about 40× faster than
opening it on one core (README, "Choosing parameters").

## What exists

* hashcat's kernels (`internal/gpu/hashcat/`, vendored unmodified) are
  OpenCL C first: hashcat's own OpenCL backend ran its Argon2 kernel on this
  Mac when hashcat's Metal build did not. Our entry points,
  `internal/gpu/kernel.cl` and `sha256.cl`, use hashcat's portable macros.
* `internal/gpu`'s `Device` API (`Open`, `Name`, `Memory`, `Batch`, `Hash`,
  `HashPartway`, `IterBatch`, `Iterate`) is all `internal/ops` uses. The
  Metal host (`metal_darwin.*`) is the model.

## What to build

* An OpenCL host, behind a build tag (e.g. `opencl`, with cgo), implementing
  the `Device` API:
  * build the expanded source with `clBuildProgram`, passing hashcat's
    OpenCL macros as `-D` options (`IS_OPENCL`, `VENDOR_ID`, …; see
    hashcat's `src/backend.c` at v8.0.0). OpenCL has an include path, so the
    expansion `source()` does for Metal is optional here;
  * Argon2id's fill exchanges words across 32 threads (hashcat uses
    sub-group shuffles or local memory per vendor): check the device's
    sub-group or wavefront size and refuse a device it cannot run on, as the
    Metal host refuses a SIMD width other than 32;
  * `Memory` is `CL_DEVICE_GLOBAL_MEM_SIZE` for a discrete card, which
    `--gpu-memory` then budgets.
* Selection: prefer Metal on macOS (OpenCL is deprecated there), CUDA where
  built and present, else OpenCL.

## Done when

* `TestMatchesXCrypto`, `TestRegisteredAlgs` and `TestIterate` pass on at
  least one OpenCL GPU and on pocl.
* `TestSealWithGPU` seals through OpenCL and opens on the CPU.
* `wickset bench` on an OpenCL GPU gives a row for the README's table.

## Open questions

* Several platforms or devices: first GPU, or `--gpu-device`?
* Keep both CUDA and OpenCL hosts, or OpenCL only, with CUDA a later
  optimization if NVIDIA throughput under OpenCL falls short?
