//go:build !wickset_testalgs

package alg

// testAlgsBuilt reports whether this build has the wickset_testalgs tag.
const testAlgsBuilt = false

// testAlgs is empty: Lookup rejects all of 0xF0–0xFF, as SPEC.md §3 requires
// of any id not marked defined.
var testAlgs [privateUseLen]Alg
