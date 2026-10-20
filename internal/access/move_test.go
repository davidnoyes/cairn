package access

import "testing"

// TestMoveIsOwnerOrManager checks the move action: the owner and a manager
// whose keys match their listing may move an item, and every other level that
// can read it is refused.
func TestMoveIsOwnerOrManager(t *testing.T) {
	allowed := map[string]Request{
		"owner":   asUser(base(), owner),
		"manager": asManager(base(), "fp-m", "fp-m"),
	}
	for name, r := range allowed {
		if got := Check(r, Move); got != Allow {
			t.Errorf("%s: got %v, want Allow", name, got)
		}
	}
	others := map[string]Request{
		"editor":                  asUser(base(), editor),
		"viewer":                  asUser(base(), viewer),
		"manager on changed keys": asManager(base(), "fp-m", "fp-other"),
		"link":                    withLink(public(base(), true)),
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
