// Command wickset seals data behind a wick: a delay that burns one step at a
// time.
//
// The wick is specified in SPEC.md, stored in a wick file with a digest; the
// encrypted payload is a second file that names its wick (CONTAINER.md).
// Files pair by name, FILE.wick with FILE.payload; either names the pair.
// Damage and mixed-up pairs are caught before burning;
// authenticity is still a signed manifest's job (SPEC.md §10).
//
// The commands live in internal/cli, and "wickset tui" starts the
// interactive interface in internal/tui; both run internal/ops.
package main

import "wickset/internal/cli"

func main() { cli.Main() }
