// Package mail sends the server's email: verification, password reset, and
// successor notices. The mailer is an interface so tests can read a link out
// of the message they would have sent.
package mail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// Message is one plain-text email.
type Message struct {
	To      string
	Subject string
	Body    string
}

// Mailer sends a message.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// New returns a mailer for a URL:
//
//   - log:// writes each message to the server log, for local testing.
//   - smtp://[user:pass@]host:port sends through an SMTP server, upgrading
//     with STARTTLS when the server offers it. Credentials are sent only over
//     TLS or to localhost.
//
// from is the sender address, such as "Cairn <cairn@example.com>".
func New(rawURL, from string, logger *slog.Logger) (Mailer, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("mail URL: %w", err)
	}
	switch u.Scheme {
	case "log":
		return &Log{Logger: logger}, nil
	case "smtp":
		if u.Host == "" {
			return nil, errors.New("mail URL: smtp:// needs a host and port")
		}
		host, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			return nil, fmt.Errorf("mail URL: %w", err)
		}
		sender, err := mail.ParseAddress(from)
		if err != nil {
			return nil, fmt.Errorf("mail sender %q: %w", from, err)
		}
		s := &SMTP{Addr: u.Host, From: sender}
		if u.User != nil {
			pass, _ := u.User.Password()
			s.Auth = smtp.PlainAuth("", u.User.Username(), pass, host)
		}
		return s, nil
	}
	return nil, fmt.Errorf("mail URL %q: scheme must be log:// or smtp://", rawURL)
}

// validate rejects a message whose headers could smuggle in others.
func validate(m Message) error {
	if strings.ContainsAny(m.To, "\r\n") || strings.ContainsAny(m.Subject, "\r\n") {
		return errors.New("mail: line break in a header")
	}
	if _, err := mail.ParseAddress(m.To); err != nil {
		return fmt.Errorf("mail: recipient %q: %w", m.To, err)
	}
	return nil
}

// Capture records messages in memory, for tests.
type Capture struct {
	mu   sync.Mutex
	msgs []Message
}

// Send records m.
func (c *Capture) Send(_ context.Context, m Message) error {
	if err := validate(m); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, m)
	return nil
}

// All returns every message sent so far.
func (c *Capture) All() []Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Message(nil), c.msgs...)
}

// Last returns the most recent message to an address, compared after
// e2e.NormalizeEmail, as the server compares addresses.
func (c *Capture) Last(to string) (Message, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.msgs) - 1; i >= 0; i-- {
		if e2e.NormalizeEmail(c.msgs[i].To) == e2e.NormalizeEmail(to) {
			return c.msgs[i], true
		}
	}
	return Message{}, false
}

// Log writes each message to a logger instead of sending it.
type Log struct {
	Logger *slog.Logger
}

// Send logs m.
func (l *Log) Send(_ context.Context, m Message) error {
	if err := validate(m); err != nil {
		return err
	}
	l.Logger.Info("mail (log:// mailer, not sent)", "to", m.To, "subject", m.Subject, "body", m.Body)
	return nil
}

// SMTP sends through an SMTP server.
type SMTP struct {
	Addr string
	From *mail.Address
	Auth smtp.Auth
}

// Send delivers m.
func (s *SMTP) Send(_ context.Context, m Message) error {
	if err := validate(m); err != nil {
		return err
	}
	to, _ := mail.ParseAddress(m.To)
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\n", s.From.String())
	fmt.Fprintf(&msg, "To: %s\r\n", to.Address)
	fmt.Fprintf(&msg, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", m.Subject))
	fmt.Fprintf(&msg, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	qp := quotedprintable.NewWriter(&msg)
	qp.Write([]byte(m.Body))
	qp.Close()
	return smtp.SendMail(s.Addr, s.Auth, s.From.Address, []string{to.Address}, msg.Bytes())
}
