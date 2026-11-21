// Package chainlock encrypts data so that it can be opened only after a
// delay: the sequential-delay lock of SPEC.md. Seal and Open are the whole
// path; the layers under them are their own packages:
//
//   - alg: the registry of step functions (SPEC.md §3)
//   - chain: the lock object, built in parallel and solved in serial, and
//     its secret, the Key
//   - format: the lock file and the payload file (CONTAINER.md)
package chainlock
