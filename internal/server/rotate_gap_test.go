package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Key rotation over an epoch a manager started: the owner holds a wrap of it
// and the artifact has no estate copy. See "Rotating keys" in
// design/e2e-api.md.

// gapWorld is an artifact whose manager started epoch 2, and the owner's
// rotation of it.
func gapWorld(t *testing.T) (*managerWorld, *rotation) {
	t.Helper()
	w := newManagerWorld(t)
	w.o.applyByManager(w.mgr, w.removeEditor())
	return w, newRotation(t, w.s, w.owner.base, w.owner, w.o)
}

// dropEpoch removes the entries of epoch from the list under key, and reports
// whether it found one.
func dropEpoch(req map[string]any, key string, epoch int) bool {
	keep := []any{}
	found := false
	for _, e := range req[key].([]any) {
		if e.(map[string]any)["epoch"] == epoch {
			found = true
			continue
		}
		keep = append(keep, e)
	}
	req[key] = keep
	return found
}

// An epoch with no estate copy may be left out of both wraps and estate: the
// owner's wrap stays as it was, under the old fingerprint, and no estate copy
// appears for it. A new epoch from the rotation still gets its copy.
func TestRotateLeavesOutAnEpochWithNoEstateCopy(t *testing.T) {
	for _, next := range []bool{false, true} {
		name := "keep epochs"
		if next {
			name = "new epoch"
		}
		t.Run(name, func(t *testing.T) {
			w, r := gapWorld(t)
			r.next[w.o.id] = next
			req := r.request()
			if !dropEpoch(req, "wraps", 2) || !dropEpoch(req, "estate", 2) {
				t.Fatal("the request had no wrap or no estate copy of epoch 2 to drop")
			}
			before := heldWraps(t, w.s, w.owner.id)
			if got, msg, _ := r.post(w.owner.testClient, req); got != http.StatusOK {
				t.Fatalf("status %d %q, want 200", got, msg)
			}
			if after := heldWraps(t, w.s, w.owner.id); len(before) != 1 || len(after) != 1 || after[0] != before[0] || after[0].fp != w.owner.keys.fp() {
				t.Errorf("held wraps after = %+v, want %+v untouched under the old fingerprint", after, before)
			}
			estate, err := w.s.store.EstateKeys(w.o.id)
			if err != nil {
				t.Fatal(err)
			}
			var got []int
			for _, e := range estate {
				got = append(got, e.Epoch)
			}
			want := []int{1}
			if next {
				want = []int{1, 3}
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("estate epochs = %v, want %v", got, want)
			}
		})
	}
}

// Leaving an epoch out is all or nothing: a wrap without its estate copy, an
// estate copy without its wrap, and a wrap or copy of an epoch that has an
// estate copy, are each refused and change nothing.
func TestRotateRefusesALoneOmissionAtAGap(t *testing.T) {
	cases := []struct {
		name   string
		want   int
		msg    string
		setup  func(t *testing.T, w *managerWorld)
		mutate func(req map[string]any) bool
	}{
		{name: "the estate copy only", want: 409, msg: "its wrap is sent", mutate: func(req map[string]any) bool {
			return dropEpoch(req, "estate", 2)
		}},
		{name: "the wrap only", want: 409, msg: "its estate copy is sent", mutate: func(req map[string]any) bool {
			return dropEpoch(req, "wraps", 2)
		}},
		{name: "the wrap of an epoch with an estate copy", want: 409, msg: "missing the wrap",
			setup: func(t *testing.T, w *managerWorld) {
				w.owner.mustDo("PUT", w.base()+"/estate/2", map[string]any{"sealed": testEstate(t, w.o.id, 2)["sealed"]}, nil, http.StatusOK)
			},
			mutate: func(req map[string]any) bool { return dropEpoch(req, "wraps", 2) }},
		{name: "the estate copy of an epoch that had one", want: 400, msg: "has no copy for epoch 1", mutate: func(req map[string]any) bool {
			return dropEpoch(req, "estate", 1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, r := gapWorld(t)
			if tc.setup != nil {
				tc.setup(t, w)
			}
			req := r.request()
			if !tc.mutate(req) {
				t.Fatal("nothing to drop")
			}
			before := wrapDump(t, w.s)
			got, msg, _ := r.post(w.owner.testClient, req)
			if got != tc.want || !strings.Contains(msg, tc.msg) {
				t.Errorf("status %d %q, want %d containing %q", got, msg, tc.want, tc.msg)
			}
			if after := wrapDump(t, w.s); after != before {
				t.Errorf("a refused rotation changed the wraps:\n%s\nwas\n%s", after, before)
			}
		})
	}
}
