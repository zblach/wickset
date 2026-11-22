# hashcat's Argon2 and SHA-256 kernels, vendored

These files are hashcat's, unmodified, from the `v8.0.0` tag of
https://github.com/hashcat/hashcat: `OpenCL/inc_*` and `docs/license.txt`
(MIT). `SHA256SUMS` records each one, and `TestVendored` fails if any of them
changes, so they are never edited here.

They are the hashing wickset runs on a GPU, written once by hashcat for
CUDA, HIP, Metal and OpenCL: Argon2 (`inc_hash_argon2.*`, by the Netherlands
Forensic Institute after Ondrej Mosnáček's argon2-gpu, over
`inc_hash_blake2b.*`) and SHA-256 (`inc_hash_sha256.*`). `../kernel.cl` and
`../sha256.cl` are wickset's own entry points into them; the package's
tests hold every result to x/crypto's Argon2id and Go's SHA-256.

To update: replace the files with those of a newer tag, regenerate the sums
(`shasum -a 256 inc_* license.txt > SHA256SUMS`), and run the tests on a GPU.
