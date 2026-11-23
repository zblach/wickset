//go:build libsodium && cgo && !libsodium_static

package sodium

// The installed shared library; a libsodium_static build names its archive
// in CGO_LDFLAGS instead (sodium.go).

/*
#cgo darwin LDFLAGS: -L/opt/homebrew/lib -L/usr/local/lib -lsodium
#cgo !darwin LDFLAGS: -lsodium
*/
import "C"
