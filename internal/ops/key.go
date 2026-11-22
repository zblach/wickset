package ops

import (
	"errors"

	"wickset/internal/store"
	"wickset/wick"
)

var errNoStream = errors.New("'-' is not available here; give the key file a path")

// checkKeyOut refuses, before anything slow is done, "-" when there is no
// Stdout for it, and a key file that already exists.
func (e *Env) checkKeyOut(path string) error {
	switch path {
	case "":
		return nil
	case "-":
		if e.Stdout == nil {
			return errNoStream
		}
		return nil
	}
	if err := store.Absent(path); err != nil { // an existing key file may be another wick's only shortcut
		return err
	}
	return store.CheckOutput(path)
}

// checkOutputs refuses, before anything slow is done, any path an
// operation's output could not be written to (store.CheckOutput): finding
// out after the delay would waste it.
func checkOutputs(paths ...string) error {
	for _, p := range paths {
		if err := store.CheckOutput(p); err != nil {
			return err
		}
	}
	return nil
}

// writeKey saves key to path, to Stdout for "-", or nowhere for "".
func (e *Env) writeKey(path string, key wick.Key) error {
	switch path {
	case "":
		return nil
	case "-":
		return store.WriteKey(e.Stdout, key)
	}
	if err := store.WriteKeyFile(path, key); err != nil {
		return err
	}
	e.note(Wrote, "wrote key to %s: it opens the encrypted file at once, without solving", path)
	return nil
}

// readKey reads a key from path, or from Stdin for "-", warning when others
// could read its file.
func (e *Env) readKey(path string) (wick.Key, error) {
	if path == "-" {
		if e.Stdin == nil {
			return nil, errNoStream
		}
		return store.ReadKey(e.Stdin)
	}
	key, exposed, err := store.ReadKeyFile(path)
	if exposed != 0 {
		e.note(Warning, "key file %s is readable by others (mode %v)", path, exposed)
	}
	return key, err
}
