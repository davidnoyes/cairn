package access

import "testing"

// TestMoveIsOwnerOnly checks the move action: the owner alone may move an
// item, and every other level that can read it is refused.
func TestMoveIsOwnerOnly(t *testing.T) {
	if got := Check(asUser(base(), owner), Move); got != Allow {
		t.Errorf("owner: got %v, want Allow", got)
	}
	others := map[string]Request{
		"editor":  asUser(base(), editor),
		"viewer":  asUser(base(), viewer),
		"manager": asManager(base(), "fp-m", "fp-m"),
		"link":    withLink(public(base(), true)),
	}
	for name, r := range others {
		if got := Check(r, Move); got != Forbidden {
			t.Errorf("%s: got %v, want Forbidden", name, got)
		}
	}
	if got := Check(asUser(base(), someone), Move); got != NotFound {
		t.Errorf("stranger: got %v, want NotFound", got)
	}
}
