//go:build unix

package store

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestCheckOutput: before any work, an output path is refused where it
// could not be written, and taken where it could: a new file, an existing
// one, a device or a pipe.
func TestCheckOutput(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing")
	os.WriteFile(existing, []byte("x"), 0o600)
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	readOnly := filepath.Join(dir, "ro")
	os.Mkdir(readOnly, 0o500)
	defer os.Chmod(readOnly, 0o700)

	for path, want := range map[string]string{
		filepath.Join(dir, "new"):          "",
		existing:                           "",
		"/dev/null":                        "",
		fifo:                               "",
		dir:                                "is a directory",
		filepath.Join(dir, "missing", "x"): "no such file or directory",
		filepath.Join(readOnly, "x"):       "permission denied",
	} {
		err := CheckOutput(path)
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: %v, want it taken", path, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: %v, want %q", path, err, want)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 3 { // existing, fifo, ro, and nothing left over
		t.Errorf("checking left files behind: %v", entries)
	}
}

// TestWriteFileDirect: a device or pipe is written directly, not replaced
// by a rename (which would put a regular file where the device was).
func TestWriteFileDirect(t *testing.T) {
	if err := WriteFile("/dev/null", []byte("gone")); err != nil {
		t.Fatalf("/dev/null: %v", err)
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte)
	go func() {
		f, _ := os.Open(fifo)
		b, _ := io.ReadAll(f)
		f.Close()
		got <- b
	}()
	if err := WriteFile(fifo, []byte("through the pipe")); err != nil {
		t.Fatal(err)
	}
	if b := <-got; !bytes.Equal(b, []byte("through the pipe")) {
		t.Fatalf("read %q", b)
	}
	if fi, err := os.Lstat(fifo); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("the pipe was replaced: %v %v", fi, err)
	}
}
