## What and why

<!-- Submitting benchmark rows? Use the benchmark template instead:
     add ?template=benchmark.md to this page's URL. -->

## Checks

- [ ] `go vet ./...` and `go test -short ./...` pass
- [ ] `go test -tags wickset_testalgs ./...` passes, for CLI or TUI changes
- [ ] No change to the wire format (SPEC.md, CONTAINER.md), or the change is
      deliberate, documented there, and the test vectors are regenerated
- [ ] Vendored files (x/crypto's Argon2id, hashcat kernels, Go's SHA-256
      assembly) unchanged, or re-vendored with their checksums updated
- [ ] No keys, sealed files or plaintexts committed, except the samples in `examples/`
