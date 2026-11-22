// Package wickset encrypts data so that it can be opened only after a delay:
// the wick of SPEC.md, burned one step at a time. Seal and Open are the
// whole path; the layers under them are their own packages:
//
//   - alg: the registry of step functions (SPEC.md §3)
//   - wick: the wick, built in parallel and burned in serial, and its
//     secret, the Key
//   - format: the wick file and the payload file (CONTAINER.md)
package wickset
