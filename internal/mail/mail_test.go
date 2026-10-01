package mail

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"mime/quotedprintable"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
)

func TestCaptureRecordsMessages(t *testing.T) {
	c := &Capture{}
	ctx := context.Background()
	if err := c.Send(ctx, Message{To: "a@example.com", Subject: "one", Body: "first"}); err != nil {
		t.Fatal(err)
	}
	c.Send(ctx, Message{To: "b@example.com", Subject: "two", Body: "second"})
	c.Send(ctx, Message{To: "A@example.com", Subject: "three", Body: "third"})
	if got := len(c.All()); got != 3 {
		t.Fatalf("All() has %d messages, want 3", got)
	}
	last, ok := c.Last("a@example.com")
	if !ok || last.Subject != "three" {
		t.Errorf("Last(a) = %+v, %v; want subject three (addresses compare case-insensitively)", last, ok)
	}
	if _, ok := c.Last("nobody@example.com"); ok {
		t.Errorf("Last(nobody) found a message")
	}
}

func TestCaptureConcurrentSend(t *testing.T) {
	c := &Capture{}
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Send(ctx, Message{To: "a@example.com", Subject: "s", Body: "b"})
			c.All()
		}()
	}
	wg.Wait()
	if got := len(c.All()); got != 50 {
		t.Fatalf("All() has %d messages, want 50", got)
	}
}

func TestSendRejectsHeaderInjection(t *testing.T) {
	c := &Capture{}
	for _, m := range []Message{
		{To: "a@example.com\r\nBcc: evil@example.com", Subject: "s", Body: "b"},
		{To: "a@example.com", Subject: "s\nBcc: evil@example.com", Body: "b"},
		{To: "not an address", Subject: "s", Body: "b"},
	} {
		if err := c.Send(context.Background(), m); err == nil {
			t.Errorf("Send(%q, %q) succeeded", m.To, m.Subject)
		}
	}
	if len(c.All()) != 0 {
		t.Errorf("rejected messages were recorded")
	}
}

func TestNewLogMailer(t *testing.T) {
	var buf bytes.Buffer
	m, err := New("log://", "cairn@example.com", slog.New(slog.NewTextHandler(&buf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), Message{To: "a@example.com", Subject: "Verify", Body: "open http://x/verify?t=abc"}); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.Contains(out, "a@example.com") || !strings.Contains(out, "http://x/verify?t=abc") {
		t.Errorf("log output missing recipient or body: %s", out)
	}
}

func TestNewRejectsUnknownScheme(t *testing.T) {
	for _, u := range []string{"", "http://host", "smtp://", "file:///tmp/x"} {
		if _, err := New(u, "cairn@example.com", slog.Default()); err == nil {
			t.Errorf("New(%q) succeeded", u)
		}
	}
}

func TestNewRejectsInvalidFrom(t *testing.T) {
	if _, err := New("smtp://host:25", "not an address", slog.Default()); err == nil {
		t.Errorf("New with invalid from address succeeded")
	}
}

func TestNewSMTPRejectsHostWithoutPort(t *testing.T) {
	if _, err := New("smtp://host", "cairn@example.com", slog.Default()); err == nil {
		t.Errorf("New with a host but no port succeeded")
	}
}

// fakeSMTP accepts one message and returns what the client sent.
func fakeSMTP(t *testing.T) (addr string, got <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tp := textproto.NewConn(conn)
		var transcript strings.Builder
		tp.PrintfLine("220 fake ESMTP")
		for {
			line, err := tp.ReadLine()
			if err != nil {
				return
			}
			transcript.WriteString(line + "\n")
			switch {
			case strings.HasPrefix(line, "EHLO"):
				tp.PrintfLine("250-fake")
				tp.PrintfLine("250 AUTH PLAIN")
			case strings.HasPrefix(line, "AUTH"):
				tp.PrintfLine("235 ok")
			case strings.HasPrefix(line, "DATA"):
				tp.PrintfLine("354 go")
				data, _ := io.ReadAll(tp.DotReader())
				transcript.Write(data)
				tp.PrintfLine("250 queued")
			case strings.HasPrefix(line, "QUIT"):
				tp.PrintfLine("221 bye")
				ch <- transcript.String()
				return
			default:
				tp.PrintfLine("250 ok")
			}
		}
	}()
	return ln.Addr().String(), ch
}

func TestSMTPMailer(t *testing.T) {
	addr, got := fakeSMTP(t)
	m, err := New("smtp://user:pass@"+addr, "Cairn <cairn@example.com>", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	err = m.Send(context.Background(), Message{To: "a@example.com", Subject: "Réinitialiser", Body: "Follow http://x/reset?t=abc\n"})
	if err != nil {
		t.Fatal(err)
	}
	transcript := <-got
	for _, want := range []string{
		"MAIL FROM:<cairn@example.com>",
		"RCPT TO:<a@example.com>",
		"AUTH PLAIN",
		"To: a@example.com",
		"Subject: =?utf-8?",
	} {
		if !strings.Contains(transcript, want) {
			t.Errorf("transcript missing %q:\n%s", want, transcript)
		}
	}
	// The headers parse, and the body decodes back to the link.
	r := textproto.NewReader(bufio.NewReader(strings.NewReader(transcript[strings.Index(transcript, "From:"):])))
	h, err := r.ReadMIMEHeader()
	if err != nil || h.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Fatalf("message headers: %v, %v", h, err)
	}
	decoded, _ := io.ReadAll(quotedprintable.NewReader(r.R))
	if !strings.Contains(string(decoded), "http://x/reset?t=abc") {
		t.Errorf("decoded body missing the link: %q", decoded)
	}
}

func TestSMTPMailerAnonymous(t *testing.T) {
	addr, got := fakeSMTP(t)
	m, err := New("smtp://"+addr, "Cairn <cairn@example.com>", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), Message{To: "a@example.com", Subject: "Hi", Body: "body\n"}); err != nil {
		t.Fatal(err)
	}
	transcript := <-got
	if strings.Contains(transcript, "AUTH") {
		t.Errorf("anonymous SMTP sent AUTH:\n%s", transcript)
	}
	for _, want := range []string{"MAIL FROM:<cairn@example.com>", "RCPT TO:<a@example.com>"} {
		if !strings.Contains(transcript, want) {
			t.Errorf("transcript missing %q:\n%s", want, transcript)
		}
	}
}

// TestMailersRejectInvalidMessages exercises header-injection and
// invalid-address rejection directly on each mailer, not only Capture.
func TestMailersRejectInvalidMessages(t *testing.T) {
	addr, got := fakeSMTP(t)
	var logBuf bytes.Buffer
	smtpMailer, err := New("smtp://"+addr, "Cairn <cairn@example.com>", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	mailers := map[string]Mailer{
		"capture": &Capture{},
		"log":     &Log{Logger: slog.New(slog.NewTextHandler(&logBuf, nil))},
		"smtp":    smtpMailer,
	}
	bad := []Message{
		{To: "a@example.com\r\nBcc: evil@example.com", Subject: "s", Body: "b"},
		{To: "a@example.com", Subject: "s\nBcc: evil@example.com", Body: "b"},
		{To: "not an address", Subject: "s", Body: "b"},
	}
	for name, m := range mailers {
		for _, msg := range bad {
			if err := m.Send(context.Background(), msg); err == nil {
				t.Errorf("%s: Send(%q, %q) succeeded", name, msg.To, msg.Subject)
			}
		}
	}
	if logBuf.Len() != 0 {
		t.Errorf("log mailer wrote a rejected message: %s", logBuf.String())
	}
	select {
	case transcript := <-got:
		t.Errorf("smtp mailer sent a rejected message to the fake server:\n%s", transcript)
	default:
	}
}
