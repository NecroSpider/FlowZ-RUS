package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

const (
	tvToken = "00112233445566778899aabbccddeeff"
	tvNc    = "0123456789abcdef0123456789abcdef"
	tvNs    = "fedcba9876543210fedcba9876543210"
)

// Cross-language test vectors: WindowsServiceHelper.test.ts asserts the same two values.
func TestAuthVectors(t *testing.T) {
	if got := serverProof(tvToken, tvNc, tvNs); got != "22d63aed5e2728581eb9d9f0ff8c92d88ecb7904c63283370bf5bfbb9582f10f" {
		t.Errorf("serverProof = %s", got)
	}
	if got := clientProof(tvToken, tvNc, tvNs, []string{"start", `C:\cfg.json`, "", "0", "42"}); got != "697891738d0b577d2bede6e59bf378b9580cfe604786e6f053daf9dcf861f8a5" {
		t.Errorf("clientProof = %s", got)
	}
}

func fixedNs(b []byte) (int, error) {
	copy(b, []byte{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10})
	return len(b), nil
}

func TestServerHandshake(t *testing.T) {
	lines := []string{"start", `C:\cfg.json`, "", "0", "42"}
	req := clientProof(tvToken, tvNc, tvNs, lines) + " 5\n" + strings.Join(lines, "\n") + "\n"
	var out bytes.Buffer
	got, err := serverHandshake(&out, bufio.NewReader(strings.NewReader(req)), tvNc, tvToken, fixedNs)
	if err != nil || strings.Join(got, "|") != strings.Join(lines, "|") {
		t.Fatalf("valid handshake failed: %v %v", err, got)
	}
	if out.String() != "CHAL "+tvNs+" "+serverProof(tvToken, tvNc, tvNs)+"\n" {
		t.Fatalf("challenge line: %q", out.String())
	}
	// altered request (relaying impostor) → rejected
	bad := clientProof(tvToken, tvNc, tvNs, lines) + " 5\nstop\n" + strings.Join(lines[1:], "\n") + "\n"
	if _, err := serverHandshake(&out, bufio.NewReader(strings.NewReader(bad)), tvNc, tvToken, fixedNs); err == nil {
		t.Fatal("altered request must be rejected")
	}
	// wrong token → rejected; empty token → rejected; bad nonce → rejected
	if _, err := serverHandshake(&out, bufio.NewReader(strings.NewReader(req)), tvNc, "other", fixedNs); err == nil {
		t.Fatal("wrong token must be rejected")
	}
	if _, err := serverHandshake(&out, bufio.NewReader(strings.NewReader(req)), tvNc, "", fixedNs); err == nil {
		t.Fatal("empty token must be rejected")
	}
	if _, err := serverHandshake(&out, bufio.NewReader(strings.NewReader(req)), "xyz", tvToken, fixedNs); err == nil {
		t.Fatal("bad nonce must be rejected")
	}
	if _, err := serverHandshake(&out, bufio.NewReader(strings.NewReader(clientProof(tvToken, tvNc, tvNs, lines)+" 99\n")), tvNc, tvToken, fixedNs); err == nil {
		t.Fatal("bad count must be rejected")
	}
}
