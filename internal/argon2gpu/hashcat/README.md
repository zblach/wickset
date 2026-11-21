# hashcat's Argon2 kernel, vendored

These files are hashcat's, unmodified, from the `v8.0.0` tag of
https://github.com/hashcat/hashcat: `OpenCL/inc_*` and `docs/license.txt`
(MIT). `SHA256SUMS` records each one, and `TestVendored` fails if any of them
changes, so they are never edited here.

They are the Argon2 implementation chainlock runs on a GPU: hashcat's, by the
Netherlands Forensic Institute after Ondrej Mosnáček's argon2-gpu, written once
for CUDA, HIP, Metal and OpenCL. `../kernel.cl` is chainlock's own entry points
into it; the package's tests hold every result to x/crypto's Argon2id.

To update: replace the files with those of a newer tag, regenerate the sums
(`shasum -a 256 inc_* license.txt > SHA256SUMS`), and run the tests on a GPU.
