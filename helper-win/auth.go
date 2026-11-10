// HMAC challenge-response for the named pipe (proto v6). No build tag: pure logic, unit-tested on any host.
//
// Why: the pipe DACL lets interactive users create pipe instances, so another local user can stand up a fake
// server instance; a client that sends the bearer token in clear would hand it over. With AUTH2 the token never
// crosses the pipe — the server proves knowledge of it first, then the client MACs its whole request (bound to
// both nonces, so it cannot be replayed or altered by a relaying impostor).
//
//	C→S  "AUTH2 <nc>\n"                      nc = 32 hex chars (16 random bytes)
//	S→C  "CHAL <ns> <serverProof>\n"         ns = 32 hex chars
//	C→S  "<clientProof> <n>\n" + n lines      the request lines (command + args), 1 ≤ n ≤ 16
//	serverProof = hex(HMAC-SHA256(token, "flowz-helper-server\n" + nc + "\n" + ns))
//	clientProof = hex(HMAC-SHA256(token, "flowz-helper-client\n" + nc + "\n" + ns + "\n" + join(lines, "\n")))
//
// The legacy form (line 1 = token) is still accepted so clients predating v6 keep working until the app
// records that the installed helper speaks AUTH2 (WindowsServiceHelper never falls back after that).
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	authPrefix   = "AUTH2 "
	maxAuthLines = 16
	maxAuthLine  = 8192
)

func macHex(token, msg string) string {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

func serverProof(token, nc, ns string) string {
	return macHex(token, "flowz-helper-server\n"+nc+"\n"+ns)
}

func clientProof(token, nc, ns string, lines []string) string {
	return macHex(token, "flowz-helper-client\n"+nc+"\n"+ns+"\n"+strings.Join(lines, "\n"))
}

func isHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func readAuthLine(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		frag, isPrefix, err := r.ReadLine()
		if err != nil {
			return "", err
		}
		b.Write(frag)
		if b.Len() > maxAuthLine {
			return "", errors.New("line too long")
		}
		if !isPrefix {
			return strings.TrimRight(b.String(), "\r"), nil
		}
	}
}

// serverHandshake runs the server side after the "AUTH2 <nc>" line was read. Returns the authenticated request lines.
func serverHandshake(w io.Writer, r *bufio.Reader, nc, token string, randRead func([]byte) (int, error)) ([]string, error) {
	nc = strings.TrimSpace(nc)
	if token == "" || !isHexLen(nc, 32) {
		return nil, errors.New("bad hello")
	}
	nsb := make([]byte, 16)
	if _, err := randRead(nsb); err != nil {
		return nil, err
	}
	ns := hex.EncodeToString(nsb)
	if _, err := fmt.Fprintf(w, "CHAL %s %s\n", ns, serverProof(token, nc, ns)); err != nil {
		return nil, err
	}
	hdr, err := readAuthLine(r)
	if err != nil {
		return nil, err
	}
	parts := strings.Fields(hdr)
	if len(parts) != 2 {
		return nil, errors.New("bad proof header")
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil || n < 1 || n > maxAuthLines {
		return nil, errors.New("bad line count")
	}
	lines := make([]string, n)
	for i := range lines {
		if lines[i], err = readAuthLine(r); err != nil {
			return nil, err
		}
	}
	if !hmac.Equal([]byte(strings.ToLower(parts[0])), []byte(clientProof(token, nc, ns, lines))) {
		return nil, errors.New("bad proof")
	}
	return lines, nil
}
