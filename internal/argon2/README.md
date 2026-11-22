# x/crypto's Argon2, vendored, cancellable

The `.go` and `.s` files and `LICENSE` (BSD-3-Clause) are
`golang.org/x/crypto/argon2` from x/crypto v0.59.0, with one change:
`argon2.go` takes a context, checked at each of Argon2's four sync points a
pass, and exports `IDKeyContext`. `argon2.go.patch` is that change, every line
of it; nothing else differs, and the changed lines say `[chainlock]`.
`argon2_test.go`, with RFC 9106's vectors, is x/crypto's own and unchanged.

`SHA256SUMS` records the files as vendored, and `TestVendored` fails if any
changes. `hasher.go` and `chainlock_test.go` are chainlock's: the API every
Argon2id backend implements (`Hasher`: this CPU one, and the GPU in
`internal/argon2gpu`), and the tests holding this copy to x/crypto itself.

To update: copy the files of a newer x/crypto, re-apply the patch
(`patch argon2.go < argon2.go.patch`), regenerate the sums
(`shasum -a 256 *.go *.s LICENSE > SHA256SUMS`, then remove our own files'
lines), and run the tests.
