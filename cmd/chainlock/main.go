// Command chainlock seals data behind a sequential-delay lock.
//
// The lock is the object specified in SPEC.md, stored in a lock file with a
// digest; the encrypted payload is a second file that names its lock
// (CONTAINER.md). Files pair by name, FILE.lock with FILE.payload, or travel
// together as FILE.chainlock.tar. Damage and mixed-up pairs are caught before
// solving; authenticity is still a signed manifest's job (SPEC.md §10).
//
// The commands live in internal/cli, and "chainlock tui" starts the
// interactive interface in internal/tui; both run internal/ops.
package main

import "chainlock/internal/cli"

func main() { cli.Main() }
