package tui

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"wickset/internal/ops"
)

// The form fields' validators, and the parsing they share with args.

func existingFile(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("required")
	}
	fi, err := os.Stat(expandHome(s))
	if err != nil {
		return errors.New("no such file")
	}
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	return nil
}

// keyPath validates a key file path. A key is never typed in, and "-" (a
// standard stream) belongs to the TUI.
func keyPath(required bool) func(string) error {
	return func(s string) error {
		s = strings.TrimSpace(s)
		switch {
		case s == "-":
			return errors.New("'-' is not available here; give a path")
		case s == "" && required:
			return errors.New("required")
		case strings.HasPrefix(s, "wickset-key-"):
			return errors.New("that is a key, not a path to one; clear it and save the key to a file")
		case required:
			return existingFile(s)
		}
		return nil
	}
}

// parseSteps reads a step count or a delay such as 8h or 2w (ops.ParseDelay).
func parseSteps(s string) (n int, d time.Duration, err error) {
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		return n, 0, nil
	}
	if d, err = ops.ParseDelay(s); err != nil {
		return 0, 0, errors.New("give a delay, such as 90s, 8h, 3d or 2w, or a number of steps")
	}
	return 0, d, nil
}

// stepsValidator accepts a delay, or a step count of at least min.
func stepsValidator(min int) func(string) error {
	return func(s string) error {
		n, d, err := parseSteps(s)
		if err == nil && d == 0 && n < min {
			return fmt.Errorf("at least %d", min)
		}
		return err
	}
}

// workersValidator accepts a whole number of workers, 0 or -1 for one per
// core, or nothing (also one per core).
func workersValidator(s string) error {
	if s = strings.TrimSpace(s); s == "" {
		return nil
	}
	if n, err := strconv.Atoi(s); err != nil || n < -1 {
		return errors.New("a whole number; 0 or -1 for one per core")
	}
	return nil
}
