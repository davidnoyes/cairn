package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/aloisdeniel/cairn/internal/client"
)

const successorUsage = `usage: cairn successor <subcommand>
  cairn successor code                                         Print your own successor code
  cairn successor status [--json]                              Show your successor, any request, and who nominated you
  cairn successor nominate USER --code CODE [--password-stdin] Check the code, then nominate USER
  cairn successor remove                                       Remove your successor
  cairn successor refuse                                       Refuse a pending request for access
  cairn successor request USER                                 Ask for access to the artifacts of a user who nominated you
  cairn successor notice-email ADDRESS [--password-stdin]      Set a personal address for notices; "" clears it`

// The Cairn-Notice warnings. Every command prints each one at most once per
// run, to stderr, so a --json command's stdout stays clean.
var noticed = map[string]bool{}

var noticeWarnings = map[string]string{
	"succession-requested": "warning: your successor asked for access to the artifacts you own. If you did not expect this, refuse with: cairn successor refuse",
	"rotate-keys":          "warning: your successor was released and can read the artifacts you own. No other change is allowed until you run: cairn rotate-keys",
}

// successorOnly is set when this run reached an artifact only as its owner's
// released successor, who reads and changes nothing.
var successorOnly bool

// successorWriteRefusals are the client's refusals of a write by someone who
// is neither the owner nor an editor.
var successorWriteRefusals = []error{
	client.ErrCannotPush, client.ErrCannotRename, client.ErrNotOwner, client.ErrCannotReseal,
	client.ErrTransferNotOwner, client.ErrVouchNotOwner, client.ErrNotApprover,
}

// successorAdvice explains err when it is a refused write and the run reached
// an artifact as a successor: the server's 403 and the client's own refusals
// do not say why. It is "" for any other error.
func successorAdvice(err error) string {
	var apiErr *client.APIError
	refused := errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden
	for _, e := range successorWriteRefusals {
		refused = refused || errors.Is(err, e)
	}
	if !successorOnly || !refused {
		return ""
	}
	return "you reach this artifact only as its owner's successor, who can read it and change nothing"
}

// watchNotices makes c print the warning for each Cairn-Notice a response
// carries, and starts a run with none printed.
func watchNotices(c *client.Client) {
	noticed, successorOnly = map[string]bool{}, false
	c.OnNotice = func(n string) {
		if w, ok := noticeWarnings[n]; ok && !noticed[n] {
			noticed[n] = true
			fmt.Fprintln(os.Stderr, w)
		}
	}
}

func runSuccessor(args []string) error {
	if len(args) == 0 {
		return errors.New(successorUsage)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "code":
		return successorCode(rest)
	case "status":
		return successorStatus(rest)
	case "nominate":
		return successorNominate(rest)
	case "remove":
		return successorRemove(rest)
	case "refuse":
		return successorRefuse(rest)
	case "request":
		return successorRequest(rest)
	case "notice-email":
		return successorNoticeEmail(rest)
	default:
		return fmt.Errorf("unknown successor subcommand %q\n%s", sub, successorUsage)
	}
}

// day is the date part of an RFC 3339 time, or s as it is.
func day(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func successorCode(args []string) error {
	fs := flag.NewFlagSet("successor code", flag.ExitOnError)
	if _, err := parsePositional(fs, args, 0, "cairn successor code"); err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	code, err := c.SuccessorCode()
	if err != nil {
		return explainRefusal(c, err)
	}
	fmt.Println(code)
	return nil
}

func successorStatus(args []string) error {
	fs := flag.NewFlagSet("successor status", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	if _, err := parsePositional(fs, args, 0, "cairn successor status [--json]"); err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	mine, err := c.MySuccessor()
	if err != nil {
		return err
	}
	from, err := c.Successions()
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(successorStatusJSON(mine, from))
	}
	if mine.Successor == nil {
		fmt.Println("you have no successor")
	} else {
		fmt.Printf("your successor is %s (%s), nominated %s\n", mine.Successor.Email, mine.Successor.ID, day(mine.NominatedAt))
		switch r := mine.Request; {
		case r == nil:
			fmt.Println("no request is pending")
		case r.Released:
			fmt.Printf("they asked on %s and were released on %s; run cairn rotate-keys to end their access\n", day(r.RequestedAt), day(r.ReleaseAt))
		default:
			fmt.Printf("they asked on %s; access starts on %s unless you run cairn successor refuse\n", day(r.RequestedAt), day(r.ReleaseAt))
		}
	}
	for _, s := range from {
		fmt.Printf("%s (%s) nominated you on %s: %s\n", s.User.Email, s.User.ID, day(s.NominatedAt), successionState(s))
	}
	return nil
}

// successionState says where a nomination of the caller stands.
func successionState(s client.Succession) string {
	switch {
	case s.Released:
		return fmt.Sprintf("released on %s, you can read the artifacts they own", day(s.ReleaseAt))
	case s.RequestedAt != "":
		return fmt.Sprintf("you asked on %s; access starts on %s", day(s.RequestedAt), day(s.ReleaseAt))
	}
	return fmt.Sprintf("you have not asked; cairn successor request %s", s.User.Email)
}

func successorStatusJSON(mine *client.SuccessorStatus, from []client.Succession) map[string]any {
	out := map[string]any{"successor": nil, "request": mine.Request, "nominatedAt": mine.NominatedAt}
	if mine.Successor != nil {
		out["successor"] = map[string]any{"id": mine.Successor.ID, "name": mine.Successor.Name, "email": mine.Successor.Email, "fp": mine.Successor.FP}
	}
	nominators := []map[string]any{}
	for _, s := range from {
		nominators = append(nominators, map[string]any{
			"id": s.User.ID, "name": s.User.Name, "email": s.User.Email, "nominatedAt": s.NominatedAt,
			"requestedAt": s.RequestedAt, "releaseAt": s.ReleaseAt, "released": s.Released,
		})
	}
	out["nominatedYou"] = nominators
	return out
}

func successorNominate(args []string) error {
	const usage = "cairn successor nominate USER --code CODE [--password-stdin]"
	fs := flag.NewFlagSet("successor nominate", flag.ExitOnError)
	code := fs.String("code", "", "the successor code the user reads with cairn successor code")
	pwStdin := fs.Bool("password-stdin", false, "read the password from stdin (one line)")
	pos, err := parsePositional(fs, args, 1, usage)
	if err != nil {
		return err
	}
	if *code == "" {
		return fmt.Errorf("usage: %s", usage)
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	u, err := c.CheckSuccessorCode(pos[0], *code)
	if err != nil {
		return explainRefusal(c, err)
	}
	password, err := readPasswordOrStdin(*pwStdin, "password: ")
	if err != nil {
		return err
	}
	seq, err := c.NominateSuccessor(*u, password)
	if err != nil {
		return explainRefusal(c, err)
	}
	fmt.Printf("%s (%s) is your successor (record %d)\nfingerprint %s\n", u.Email, u.ID, seq, showFP(u.FP))
	fmt.Printf("they can read the artifacts you own 14 days after they ask, unless you refuse first with: cairn successor refuse\n")
	return nil
}

func successorRemove(args []string) error {
	fs := flag.NewFlagSet("successor remove", flag.ExitOnError)
	if _, err := parsePositional(fs, args, 0, "cairn successor remove"); err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	u, err := c.RemoveSuccessor()
	if err != nil {
		return explainRefusal(c, err)
	}
	fmt.Printf("%s is no longer your successor\n", u.Email)
	return nil
}

func successorRefuse(args []string) error {
	fs := flag.NewFlagSet("successor refuse", flag.ExitOnError)
	if _, err := parsePositional(fs, args, 0, "cairn successor refuse"); err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	if err := c.RefuseSuccession(); err != nil {
		return err
	}
	fmt.Println("refused the request; your successor stays nominated and was told")
	return nil
}

func successorRequest(args []string) error {
	fs := flag.NewFlagSet("successor request", flag.ExitOnError)
	pos, err := parsePositional(fs, args, 1, "cairn successor request USER")
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	s, err := c.RequestSuccession(pos[0])
	if err != nil {
		return explainRefusal(c, err)
	}
	fmt.Printf("asked for access to the artifacts %s owns; they were told, and can refuse\naccess starts on %s unless they do\n", s.User.Email, day(s.ReleaseAt))
	return nil
}

func successorNoticeEmail(args []string) error {
	const usage = "cairn successor notice-email ADDRESS [--password-stdin]"
	fs := flag.NewFlagSet("successor notice-email", flag.ExitOnError)
	pwStdin := fs.Bool("password-stdin", false, "read the password from stdin (one line)")
	pos, err := parsePositional(fs, args, 1, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	password, err := readPasswordOrStdin(*pwStdin, "password: ")
	if err != nil {
		return err
	}
	pending, err := c.SetNoticeEmail(pos[0], password)
	switch {
	case err != nil:
		return err
	case pos[0] == "":
		fmt.Println("cleared your notice address")
	case pending:
		fmt.Printf("check %s for a link that verifies it; notices go there once you follow it\n", pos[0])
	default:
		fmt.Printf("notices go to %s\n", pos[0])
	}
	return nil
}
