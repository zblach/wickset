package chain

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestKeyEncoding(t *testing.T) {
	k := Key(secretFor(testAlg32, 0x50))
	text := k.Encode()
	if !strings.HasPrefix(text, "chainlock-key-v1:") || strings.ContainsAny(text, "+/=") {
		t.Fatalf("encoding %q: want the prefix and unpadded URL-safe base64", text)
	}
	got, err := ParseKey(" " + text + "\n")
	if err != nil || !bytes.Equal(got, k) {
		t.Fatalf("round trip: %v", err)
	}
	for _, bad := range []string{
		"",
		strings.TrimPrefix(text, "chainlock-key-v1:"), // no prefix
		"chainlock-key-v2:" + text[len("chainlock-key-v1:"):],
		text + "!",                     // not base64
		Key(make([]byte, 20)).Encode(), // not an AES key size
	} {
		if _, err := ParseKey(bad); !errors.Is(err, ErrKey) {
			t.Errorf("ParseKey(%q): err %v, want ErrKey", bad, err)
		}
	}
}

// TestKeyRedacted: no formatting verb prints a key's bytes or its encoding.
func TestKeyRedacted(t *testing.T) {
	k := Key(secretFor(testAlg32, 0x50))
	enc := k.Encode()
	raw := fmt.Sprintf("%x", []byte(k))
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
		out := fmt.Sprintf(verb, k)
		if strings.Contains(out, raw) || strings.Contains(out, enc) || !strings.Contains(out, "redacted") {
			t.Errorf("%s printed %q", verb, out)
		}
	}
	if out := fmt.Sprint(struct{ K Key }{k}); strings.Contains(out, raw) {
		t.Errorf("in a struct: %q", out)
	}
}
