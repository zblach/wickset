package store

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ErrArchive reports a tar that is not a wickset archive (CONTAINER.md §4).
var ErrArchive = errors.New("not a wickset archive")

// isArchive reports a tar archive (CONTAINER.md §1). Containers start with
// 0x00 and are checked first; a tar never does.
func isArchive(b []byte) bool {
	return len(b) > 262 && b[0] != 0x00 && string(b[257:262]) == "ustar"
}

// readArchive returns the members of an archive: exactly NAME.wick and
// NAME.payload, regular files with no directory part (CONTAINER.md §4).
func readArchive(b []byte) (name string, wickFile, payload []byte, err error) {
	var wickName, payloadName string
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, nil, fmt.Errorf("%w: %v", ErrArchive, err)
		}
		if h.Typeflag != tar.TypeReg || strings.ContainsAny(h.Name, `/\`) {
			return "", nil, nil, fmt.Errorf("%w: unexpected member %q", ErrArchive, h.Name)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return "", nil, nil, fmt.Errorf("%w: %v", ErrArchive, err)
		}
		switch {
		case strings.HasSuffix(h.Name, WickSuffix) && wickFile == nil:
			wickName, wickFile = strings.TrimSuffix(h.Name, WickSuffix), data
		case strings.HasSuffix(h.Name, PayloadSuffix) && payload == nil:
			payloadName, payload = strings.TrimSuffix(h.Name, PayloadSuffix), data
		default:
			return "", nil, nil, fmt.Errorf("%w: unexpected member %q", ErrArchive, h.Name)
		}
	}
	if wickFile == nil || payload == nil || wickName != payloadName {
		return "", nil, nil, fmt.Errorf("%w: want exactly NAME.wick and NAME.payload", ErrArchive)
	}
	return wickName, wickFile, payload, nil
}

// writeArchive writes NAME.wick and NAME.payload to path as a tar.
func writeArchive(path, name string, wickFile, payload []byte) error {
	data, err := archive(name, wickFile, payload)
	if err != nil {
		return err
	}
	return WriteFile(path, data)
}

// archive is a tar of NAME.wick and NAME.payload. Headers are built by hand,
// not from file info, so the archive carries no user, group or time
// (CONTAINER.md §4).
func archive(name string, wickFile, payload []byte) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range []struct {
		name string
		data []byte
	}{{name + WickSuffix, wickFile}, {name + PayloadSuffix, payload}} {
		h := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     m.name,
			Mode:     0o600,
			Size:     int64(len(m.data)),
			ModTime:  time.Unix(0, 0),
		}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := tw.Write(m.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
