package store

import (
	"io"
	"io/fs"
	"os"

	"wickset/wick"
)

// maxKeyText bounds a key read from a stream; a key's text is under 64 bytes.
const maxKeyText = 4096

// WriteKey writes key's text form (CONTAINER.md §5) to w.
func WriteKey(w io.Writer, key wick.Key) error {
	_, err := io.WriteString(w, key.Encode()+"\n")
	return err
}

// WriteKeyFile writes key's text form to path with mode 0600.
func WriteKeyFile(path string, key wick.Key) error {
	return WriteFile(path, []byte(key.Encode()+"\n"))
}

// ReadKey reads a key's text form from r.
func ReadKey(r io.Reader) (wick.Key, error) {
	text, err := io.ReadAll(io.LimitReader(r, maxKeyText))
	if err != nil {
		return nil, err
	}
	return wick.ParseKey(string(text))
}

// ReadKeyFile reads a key's text form from path. exposed is the file's mode
// when others could read it, which callers warn about (as ssh does for a
// private key), and zero otherwise.
func ReadKeyFile(path string) (key wick.Key, exposed fs.FileMode, err error) {
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		exposed = fi.Mode().Perm()
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	key, err = ReadKey(f)
	return key, exposed, err
}
