//go:build wickset_testalgs

package alg

// This file exists for end-to-end tests only:
//
//	go test -tags wickset_testalgs ./...
//
// It defines cheap step functions in the private-use range, which SPEC.md §3
// sets aside for private testing. Their steps take nanoseconds, so a wick made
// with one has no real delay. Never ship a binary built with this tag; the CLI
// warns on every run when it is set.

import "crypto/sha256"

// testAlgsBuilt reports whether this build has the wickset_testalgs tag.
const testAlgsBuilt = true

// testAlgs holds the end-to-end algorithms. 0xF0 and 0xF1 stay empty: the
// unit tests use those ids for their own unregistered algorithms.
var testAlgs = [privateUseLen]Alg{
	0xFE - privateUse: &e2eAlg{id: 0xFE, name: "test-e2e-sha256-32", bs: 32},
	0xFF - privateUse: &e2eAlg{id: 0xFF, name: "test-e2e-sha256-16", bs: 16},
}

// e2eAlg is a cheap step: SHA-256 of name ‖ x, truncated to bs bytes.
type e2eAlg struct {
	id   ID
	name string
	bs   int
}

func (a *e2eAlg) ID() ID         { return a.id }
func (a *e2eAlg) Name() string   { return a.name }
func (a *e2eAlg) BlockSize() int { return a.bs }
func (a *e2eAlg) MemBytes() int  { return 0 }

func (a *e2eAlg) H(x []byte) []byte {
	h := sha256.Sum256(append([]byte(a.name), x...))
	return h[:a.bs]
}
