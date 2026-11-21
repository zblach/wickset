package tui

import (
	"cmp"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// pathField is the key of every input that takes a path: tab completes it.
const pathField = "path"

// expandHome reads a leading ~ as the home directory, as a shell would.
func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + path[1:]
		}
	}
	return path
}

// complete finds what completes typed as a path: the text to append, and,
// when the matches share nothing more, the matches themselves. A sole match
// completes in full, a directory with its slash so the next tab goes on in.
// Hidden files are matched only when typed asks for them with a dot.
func complete(typed string) (add string, matches []string) {
	dir, prefix := filepath.Split(typed)
	base := cmp.Or(expandHome(dir), ".")
	entries, err := os.ReadDir(base)
	if err != nil {
		return "", nil
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, prefix) || (strings.HasPrefix(name, ".") && !strings.HasPrefix(prefix, ".")) {
			continue
		}
		if e.IsDir() || isDir(filepath.Join(base, name)) { // the second follows a link
			name += string(filepath.Separator)
		}
		matches = append(matches, name)
	}
	switch len(matches) {
	case 0:
		return "", nil
	case 1:
		return matches[0][len(prefix):], nil
	}
	slices.Sort(matches)
	if common := commonPrefix(matches); len(common) > len(prefix) {
		return common[len(prefix):], nil
	}
	return "", matches
}

// isDir reports a directory at path, following links.
func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// commonPrefix is the longest prefix every one of ss shares.
func commonPrefix(ss []string) string {
	p := ss[0]
	for _, s := range ss[1:] {
		for !strings.HasPrefix(s, p) {
			p = p[:len(p)-1]
		}
	}
	for !utf8.ValidString(p) { // never end inside a character
		p = p[:len(p)-1]
	}
	return p
}
