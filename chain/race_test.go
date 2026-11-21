//go:build race

package chain

// raceEnabled: the race detector slows Argon2's loops many times over, so
// wall-clock bounds do not hold under it.
const raceEnabled = true
