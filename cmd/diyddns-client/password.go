package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// resolvePassword acquires the enrollment password without ever echoing it:
// the DIYDDNS_ENROLL_PASSWORD value (via env) first for automation, else a
// single piped stdin line when stdin is not a terminal, else a hidden no-echo
// terminal prompt. Every external effect (TTY test, hidden read) is injected so
// all branches are testable without a real terminal. An empty resolved password
// is an error. The password is never written to stderr or into an error string.
func resolvePassword(env string, stdin io.Reader, stderr io.Writer, isTTY func() bool, readHidden func() (string, error)) (string, error) {
	if env != "" {
		return env, nil
	}
	var pw string
	if isTTY() {
		_, _ = fmt.Fprint(stderr, "Password: ")
		p, err := readHidden()
		_, _ = fmt.Fprintln(stderr) // terminate the prompt line
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		pw = p
	} else {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read password: %w", err)
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	if pw == "" {
		return "", errors.New("password required (set DIYDDNS_ENROLL_PASSWORD, pipe it on stdin, or type it at the prompt)")
	}
	return pw, nil
}
