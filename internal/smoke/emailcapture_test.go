//go:build smoke

package smoke

import (
	"net"
	"net/netip"
	"net/textproto"
	"strings"
	"sync"
	"testing"
)

// capturedEnvelope is what the fake SMTP server observed for one message.
// No `from` field: nothing asserts on the envelope sender, and an unread field
// is noise.
type capturedEnvelope struct {
	to, data string
}

// startCaptureSMTP starts a minimal plaintext SMTP listener on 127.0.0.1 that
// advertises neither AUTH nor STARTTLS, accepts exactly ONE connection, and
// reports the captured envelope on the returned channel. Configure the server
// under test with tls: "none" and an empty username to match.
//
// Cleanup closes the listener BEFORE waiting on the serve goroutine: the reverse
// order deadlocks, because a pending Accept only returns once the listener is
// closed.
func startCaptureSMTP(t *testing.T) (host string, port int, envelopes <-chan capturedEnvelope) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addrPort, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parse listener addr: %v", err)
	}

	ch := make(chan capturedEnvelope, 1)
	var wg sync.WaitGroup
	wg.Go(func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		serveCaptureConn(conn, ch)
	})
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})

	return addrPort.Addr().String(), int(addrPort.Port()), ch
}

// serveCaptureConn greets the client and serves exactly one message, reporting
// the envelope on QUIT. textproto handles RFC 5321 dot-unstuffing of the DATA
// body.
func serveCaptureConn(conn net.Conn, envelopes chan<- capturedEnvelope) {
	tp := textproto.NewConn(conn)
	defer func() { _ = tp.Close() }()
	_ = tp.PrintfLine("220 capture.smtp.test ready")

	var env capturedEnvelope
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			_ = tp.PrintfLine("250 capture.smtp.test")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			_ = tp.PrintfLine("250 ok")
		case strings.HasPrefix(upper, "RCPT TO:"):
			env.to = line[len("RCPT TO:"):]
			_ = tp.PrintfLine("250 ok")
		case upper == "DATA":
			_ = tp.PrintfLine("354 go ahead")
			data, derr := tp.ReadDotBytes()
			if derr != nil {
				return
			}
			env.data = string(data)
			_ = tp.PrintfLine("250 queued")
		case upper == "QUIT":
			_ = tp.PrintfLine("221 bye")
			envelopes <- env
			return
		default:
			_ = tp.PrintfLine("250 ok")
		}
	}
}
