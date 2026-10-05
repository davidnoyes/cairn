package client

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// currentAK is the AK and epoch c writes under for the artifact.
func currentAK(t *testing.T, c *Client, artifact string) ([]byte, int) {
	t.Helper()
	k := mustUnlock(t, c)
	va, err := c.VerifyArtifact(k, artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	aks, err := c.callerAKs(k, artifact, va.Chain)
	if err != nil {
		t.Fatal(err)
	}
	epoch := va.Chain.Latest.Epoch
	return aks[epoch], epoch
}

// forgeMeta seals plain as a field the way putMeta does, signed by k, but
// with whatever bytes a test wants, so a check can be seen to refuse it.
func forgeMeta(t *testing.T, k *UnlockedKeys, artifact, vid, field string, epoch int, ak, plain []byte) MetaItem {
	t.Helper()
	blob, err := e2e.SealBlob(rand.Reader, ak, e2e.BlobContext{Artifact: artifact, Version: vid, Kind: "meta", Name: field}, plain)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(e2e.RecordBody{V: 1, Artifact: artifact, Version: vid, Kind: "meta", Name: field, Epoch: epoch, SHA256: e2e.BodyHash(blob)})
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "record", body)
	if err != nil {
		t.Fatal(err)
	}
	return MetaItem{Record: env, SignerKey: e2e.B64(k.Ed25519Pub), Blob: e2e.B64(blob)}
}

func TestMetaRoundTrip(t *testing.T) {
	c := authedClient(t)
	a, err := c.CreateArtifact("widget", "a widget")
	if err != nil {
		t.Fatalf("CreateArtifact: %v", err)
	}
	if a.Name != "widget" || a.Description != "a widget" || a.Title() != "widget" {
		t.Errorf("CreateArtifact = %+v", a)
	}
	v, err := c.Push(a.ID, "", siteDir(t), "v1", "first cut")
	if err != nil || v.Name != "v1" || v.Changelog != "first cut" {
		t.Fatalf("Push = %+v, %v", v, err)
	}

	got, err := c.GetArtifact(a.ID)
	if err != nil || got.Name != "widget" || got.Description != "a widget" {
		t.Errorf("GetArtifact = %+v, %v", got, err)
	}
	all, err := c.ListArtifacts()
	if err != nil || len(all) != 1 || all[0].Name != "widget" || all[0].Description != "a widget" {
		t.Errorf("ListArtifacts = %+v, %v", all, err)
	}
	versions, err := c.ListVersions(a.ID)
	if err != nil || len(versions) != 1 || versions[0].Name != "v1" || versions[0].Changelog != "first cut" {
		t.Errorf("ListVersions = %+v, %v", versions, err)
	}

	// The server holds sealed fields and nothing else.
	raw, err := c.getArtifact(a.ID)
	if err != nil || len(raw.Meta) != 2 || raw.Meta["name"].Blob == "" {
		t.Fatalf("the server's view = %+v, %v", raw.Meta, err)
	}
	if strings.Contains(raw.Meta["name"].Blob, "widget") {
		t.Error("the name is in the blob in the clear")
	}

	// A rename is a write of the field.
	if err := c.UpdateArtifact(a.ID, map[string]string{"name": "gadget"}); err != nil {
		t.Fatalf("UpdateArtifact: %v", err)
	}
	got, _ = c.GetArtifact(a.ID)
	if got.Name != "gadget" || got.Description != "a widget" {
		t.Errorf("after the rename: %+v, want the name changed and the description kept", got)
	}
	// Found by the new name only.
	if r, err := c.ResolveArtifact("gadget"); err != nil || r.ID != a.ID {
		t.Errorf("ResolveArtifact(gadget) = %+v, %v", r, err)
	}
	if _, err := c.ResolveArtifact("widget"); err == nil {
		t.Error("the old name still resolves")
	}
}

func TestEmptyFieldsAreNotWritten(t *testing.T) {
	c := authedClient(t)
	a, err := c.CreateArtifact("plain", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Push(a.ID, "", siteDir(t), "", ""); err != nil {
		t.Fatal(err)
	}
	raw, _ := c.getArtifact(a.ID)
	if _, ok := raw.Meta["description"]; ok || raw.Meta["name"].Blob == "" {
		t.Errorf("artifact meta = %v, want only the name", raw.Meta)
	}
	vs, _ := c.listVersions(a.ID)
	if len(vs) != 1 || len(vs[0].Meta) != 0 {
		t.Errorf("version meta = %+v, want none", vs[0].Meta)
	}
	// A replace with a name writes it, and one without leaves it.
	if _, err := c.Push(a.ID, vs[0].ID, siteDir(t), "named", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Push(a.ID, vs[0].ID, siteDir(t), "", ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.ListVersions(a.ID); got[0].Name != "named" {
		t.Errorf("name after a replace with none = %q, want it kept", got[0].Name)
	}
}

func TestUpdateRefusesAReaderAndALongField(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if err := s.bob.UpdateArtifact(s.artifact, map[string]string{"name": "mine"}); !errors.Is(err, ErrCannotRename) {
		t.Errorf("a viewer's UpdateArtifact = %v, want ErrCannotRename", err)
	}
	if err := s.ada.UpdateArtifact(s.artifact, map[string]string{"name": strings.Repeat("x", e2e.MaxMetaPlaintext+1)}); err == nil || !strings.Contains(err.Error(), "over") {
		t.Errorf("a 16 KiB + 1 name: %v, want a refusal", err)
	}
	if err := s.ada.UpdateArtifact(s.artifact, map[string]string{"name": strings.Repeat("x", e2e.MaxMetaPlaintext)}); err != nil {
		t.Errorf("a 16 KiB name: %v", err)
	}
	if err := s.ada.UpdateArtifact(s.artifact, map[string]string{"name": "bad \xff utf-8"}); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("a name that is not UTF-8: %v, want a refusal", err)
	}
}

func TestReadChecksEveryField(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	v1, err := s.ada.Push(s.artifact, "", siteDir(t), "one", "")
	if err != nil {
		t.Fatal(err)
	}
	v2, err := s.ada.Push(s.artifact, "", siteDir(t), "two", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ada.UpdateArtifact(s.artifact, map[string]string{"name": "real", "description": "desc"}); err != nil {
		t.Fatal(err)
	}
	ak, epoch := currentAK(t, s.ada, s.artifact)
	adaKeys, bobKeys := mustUnlock(t, s.ada), mustUnlock(t, s.bob)
	chk, err := s.ada.metaChecker(adaKeys, s.artifact)
	if err != nil {
		t.Fatal(err)
	}
	art, _ := s.ada.getArtifact(s.artifact)
	vers, _ := s.ada.listVersions(s.artifact)
	byID := map[string]*Version{}
	for _, v := range vers {
		byID[v.ID] = v
	}
	good := art.Meta["name"]
	if text, _, err := openMeta(chk, "", "name", good); err != nil || text != "real" {
		t.Fatalf("the good field = %q, %v", text, err)
	}

	cases := []struct {
		name  string
		vid   string
		field string
		item  MetaItem
		want  string
	}{
		{"a blob that is not the record's", "", "name",
			MetaItem{Record: good.Record, SignerKey: good.SignerKey, Blob: forgeMeta(t, adaKeys, s.artifact, "", "name", epoch, ak, []byte("other")).Blob},
			"does not match its signature"},
		{"an empty blob", "", "name",
			MetaItem{Record: good.Record, SignerKey: good.SignerKey, Blob: ""}, "the blob is empty"},
		{"a blob that is not base64", "", "name",
			MetaItem{Record: good.Record, SignerKey: good.SignerKey, Blob: "***"}, "not base64"},
		{"signed by a reader", "", "name",
			forgeMeta(t, bobKeys, s.artifact, "", "name", epoch, ak, []byte("forged")), "may not write"},
		{"a signer key that is not the writer's", "", "name",
			MetaItem{Record: good.Record, SignerKey: e2e.B64(bobKeys.Ed25519Pub), Blob: good.Blob}, "may not write"},
		{"a record that is for another field", "", "description", good, "another address"},
		{"a field of another version", v2.ID, "name", byID[v1.ID].Meta["name"], "another version"},
		{"a version field read as the artifact's", "", "name", byID[v1.ID].Meta["name"], "another version"},
		{"text that is not UTF-8", "", "name",
			forgeMeta(t, adaKeys, s.artifact, "", "name", epoch, ak, []byte("bad \xff\xfe text")), "UTF-8"},
		{"text over 16 KiB", "", "name",
			forgeMeta(t, adaKeys, s.artifact, "", "name", epoch, ak, []byte(strings.Repeat("x", e2e.MaxMetaPlaintext+1))), "over"},
		{"an epoch whose AK the reader lacks", "", "name",
			forgeMeta(t, adaKeys, s.artifact, "", "name", epoch+5, ak, []byte("future")), "no key for epoch"},
		{"a blob sealed under another AK", "", "name",
			forgeMeta(t, adaKeys, s.artifact, "", "name", epoch, make([]byte, 32), []byte("wrong key")), "does not open"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := openMeta(chk, tc.vid, tc.field, tc.item)
			if !errors.Is(err, ErrUnverified) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("openMeta = %v, want ErrUnverified naming %q", err, tc.want)
			}
		})
	}
}

// A field the server tampers with shows as unreadable and the artifact under
// its ID; it is not an error of the command.
func TestAnAlteredFieldShowsTheArtifactUnderItsID(t *testing.T) {
	s := newSharing(t)
	if err := s.ada.UpdateArtifact(s.artifact, map[string]string{"name": "real"}); err != nil {
		t.Fatal(err)
	}
	ak, epoch := currentAK(t, s.ada, s.artifact)
	forged := forgeMeta(t, mustUnlock(t, s.bob), s.artifact, "", "name", epoch, ak, []byte("forged"))
	c := keyedFor(t, s.host, mustAPIKeyOf(t, s.ada))
	intercept(c, &tamper{after: func(req *http.Request, resp *http.Response) {
		if req.Method == "GET" && strings.HasSuffix(req.URL.Path, "/api/artifacts/"+s.artifact) && resp.StatusCode == 200 {
			var view map[string]any
			if err := json.Unmarshal(readBody(t, resp), &view); err != nil {
				t.Fatal(err)
			}
			view["meta"] = map[string]any{"name": forged}
			b, _ := json.Marshal(view)
			setBody(resp, b)
		}
	}})
	got, err := c.GetArtifact(s.artifact)
	if err != nil || got.Name != "" || got.Title() != s.artifact {
		t.Fatalf("GetArtifact = %+v, %v, want no name and the ID as the title", got, err)
	}
}

// An editor's field reads while they are an editor. After they are removed it
// does not verify, until the owner's re-seal under the record before the
// removal signs it again.
func TestARemovedEditorsFieldIsUnreadableUntilTheOwnerReseals(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if err := s.bob.UpdateArtifact(s.artifact, map[string]string{"name": "bob's name", "description": "bob's words"}); err != nil {
		t.Fatalf("an editor's UpdateArtifact: %v", err)
	}
	v, err := s.bob.Push(s.artifact, "", siteDir(t), "bob's version", "bob's log")
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := s.ada.GetArtifact(s.artifact); a.Name != "bob's name" {
		t.Fatalf("an editor's name reads as %q", a.Name)
	}

	// The removal's re-seal fails: no field is written.
	failing := keyedFor(t, s.host, mustAPIKeyOf(t, s.ada))
	intercept(failing, &tamper{before: func(req *http.Request) *http.Response {
		if req.Method == "PUT" && strings.Contains(req.URL.Path, "/meta/") {
			return replyJSON(req, 500, nil, `{"error":"unavailable"}`)
		}
		return nil
	}})
	first, err := failing.Unshare(s.artifact, "bob@example.com")
	if err != nil || first.ResealErr == nil {
		t.Fatalf("Unshare = %+v, %v, want a re-seal failure", first, err)
	}

	a, err := s.ada.GetArtifact(s.artifact)
	if err != nil || a.Name != "" || a.Description != "" || a.Title() != s.artifact {
		t.Fatalf("after the removal: %+v, %v, want unreadable fields and the ID as the title", a, err)
	}
	if vs, _ := s.ada.ListVersions(s.artifact); len(vs) != 1 || vs[0].Name != "" || vs[0].Changelog != "" {
		t.Fatalf("version fields after the removal: %+v", vs)
	}

	// The owner re-seals: bob could write when the record before the change
	// was made, so each field verifies and is signed again by the owner.
	res, err := s.ada.Reseal(s.artifact)
	// The version's content waits for the owner's review, as bob signed it;
	// its fields do not.
	if err != nil || res.Meta != 4 || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], "owner's review") {
		t.Fatalf("Reseal = %+v, %v, want 4 fields and only the version's content skipped", res, err)
	}
	a, _ = s.ada.GetArtifact(s.artifact)
	if a.Name != "bob's name" || a.Description != "bob's words" {
		t.Errorf("after the re-seal: %+v", a)
	}
	vs, _ := s.ada.ListVersions(s.artifact)
	if len(vs) != 1 || vs[0].ID != v.ID || vs[0].Name != "bob's version" || vs[0].Changelog != "bob's log" {
		t.Errorf("version fields after the re-seal: %+v", vs)
	}
	again, err := s.ada.Reseal(s.artifact)
	if err != nil || again.Meta != 0 {
		t.Errorf("a second Reseal = %+v, %v, want nothing to do", again, err)
	}
}

// A later change finds the removed editor's field already outside the record
// before it, so it is left as it is and reported.
func TestResealLeavesAFieldASecondChangeCannotVerify(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if err := s.bob.UpdateArtifact(s.artifact, map[string]string{"name": "bob's name"}); err != nil {
		t.Fatal(err)
	}
	failing := keyedFor(t, s.host, mustAPIKeyOf(t, s.ada))
	intercept(failing, &tamper{before: func(req *http.Request) *http.Response {
		if req.Method == "PUT" && strings.Contains(req.URL.Path, "/meta/") {
			return replyJSON(req, 500, nil, `{"error":"unavailable"}`)
		}
		return nil
	}})
	if first, err := failing.Unshare(s.artifact, "bob@example.com"); err != nil || first.ResealErr == nil {
		t.Fatalf("Unshare = %+v, %v", first, err)
	}
	if _, err := s.ada.Public(s.artifact, true, nil); err != nil {
		t.Fatal(err)
	}
	off, err := s.ada.Public(s.artifact, false, nil)
	if err != nil || off.ResealErr != nil || off.Resealed.Meta != 0 || len(off.Resealed.Skipped) != 1 || !strings.Contains(off.Resealed.Skipped[0], "may not write") {
		t.Fatalf("Public off = %+v, %v, want bob's name skipped", off, err)
	}
	if a, _ := s.ada.GetArtifact(s.artifact); a.Name != "" {
		t.Errorf("name = %q, want it unreadable", a.Name)
	}
	// A write by the owner makes it readable again.
	if err := s.ada.UpdateArtifact(s.artifact, map[string]string{"name": "ada's name"}); err != nil {
		t.Fatal(err)
	}
	if a, _ := s.ada.GetArtifact(s.artifact); a.Name != "ada's name" {
		t.Errorf("name = %q", a.Name)
	}
}

// Every epoch change re-seals the fields under the new epoch, so the
// previous epoch's AK no longer opens them.
func TestEpochChangeResealsEveryField(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Push(s.artifact, "", siteDir(t), "v1", "log"); err != nil {
		t.Fatal(err)
	}
	if err := s.ada.UpdateArtifact(s.artifact, map[string]string{"name": "named", "description": "described"}); err != nil {
		t.Fatal(err)
	}
	oldAK, _ := currentAK(t, s.ada, s.artifact)
	if _, err := s.ada.Public(s.artifact, true, nil); err != nil {
		t.Fatal(err)
	}
	off, err := s.ada.Public(s.artifact, false, nil)
	if err != nil || off.ResealErr != nil || off.Resealed == nil || off.Resealed.Meta != 4 {
		t.Fatalf("Public off = %+v, %v, want 4 fields re-sealed", off, err)
	}
	art, _ := s.ada.getArtifact(s.artifact)
	vs, _ := s.ada.listVersions(s.artifact)
	items := map[string]MetaItem{"name": art.Meta["name"], "description": art.Meta["description"]}
	for field, item := range items {
		var body e2e.RecordBody
		if err := e2e.DecodeStrict(item.Record.Body, &body); err != nil || body.Epoch != 2 {
			t.Errorf("the artifact's %s is sealed under epoch %d (%v), want 2", field, body.Epoch, err)
		}
		blob, _ := e2e.UnB64(item.Blob)
		if _, err := e2e.OpenBlob(oldAK, e2e.BlobContext{Artifact: s.artifact, Kind: "meta", Name: field}, blob); err == nil {
			t.Errorf("the old epoch's AK opens the %s", field)
		}
	}
	for _, item := range vs[0].Meta {
		var body e2e.RecordBody
		if err := e2e.DecodeStrict(item.Record.Body, &body); err != nil || body.Epoch != 2 {
			t.Errorf("a version field is sealed under epoch %d (%v), want 2", body.Epoch, err)
		}
	}
	if a, _ := s.ada.GetArtifact(s.artifact); a.Name != "named" || a.Description != "described" {
		t.Errorf("after the re-seal: %+v", a)
	}
}

// A server that serves an older record than the keyring pins gets no write.
func TestUpdateArtifactRefusesAnEpochBelowThePin(t *testing.T) {
	s := newSharing(t)
	k := mustUnlock(t, s.ada)
	m, _ := s.ada.Membership(s.artifact)
	if _, err := s.ada.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Epochs[s.artifact] = e2e.KeyringEpoch{Epoch: 3, Seq: 1, Head: e2e.BodyHash(m.Records[0].Body)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.ada.UpdateArtifact(s.artifact, map[string]string{"name": "x"}); !errors.Is(err, e2e.ErrStaleEpoch) {
		t.Errorf("UpdateArtifact under an epoch older than the pin: %v, want ErrStaleEpoch", err)
	}
}

func TestPutMetaRefusesAStaleEpoch(t *testing.T) {
	s := newSharing(t)
	k := mustUnlock(t, s.ada)
	ak, epoch := currentAK(t, s.ada, s.artifact)
	if _, err := s.ada.Public(s.artifact, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.Public(s.artifact, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.ada.putMeta(k, s.artifact, "", "name", epoch, ak, "stale"); !errors.Is(err, ErrEpochMoved) {
		t.Errorf("putMeta under the old epoch = %v, want ErrEpochMoved", err)
	}
}

func TestResourcesAreBlindIndexed(t *testing.T) {
	s := newSharing(t)
	other, err := s.ada.CreateArtifact("other", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ada.AddResource(s.artifact, "claude-session", "sess-1"); err != nil {
		t.Fatalf("AddResource: %v", err)
	}
	if err := s.ada.AddResource(other.ID, "jira", "KEY-1"); err != nil {
		t.Fatal(err)
	}
	// The server holds the index, not the reference.
	raw, _ := s.ada.getArtifact(s.artifact)
	if len(raw.Resources) != 1 || raw.Resources[0].Type != "claude-session" {
		t.Fatalf("resources = %+v", raw.Resources)
	}
	k := mustUnlock(t, s.ada)
	want, _ := e2e.BlindIndex(k.IndexKey, "claude-session", "sess-1")
	if raw.Resources[0].Value != want || strings.Contains(raw.Resources[0].Value, "sess") {
		t.Errorf("the stored value = %q, want the blind index %s", raw.Resources[0].Value, want)
	}

	if a, err := s.ada.ResolveArtifact("sess-1"); err != nil || a.ID != s.artifact {
		t.Errorf("ResolveArtifact(sess-1) = %+v, %v", a, err)
	}
	if a, err := s.ada.ResolveArtifact("KEY-1"); err != nil || a.ID != other.ID {
		t.Errorf("ResolveArtifact(KEY-1) = %+v, %v", a, err)
	}
	// The type is part of the index: the reference under another type is not it.
	if _, err := s.ada.ResolveArtifact("sess-2"); err == nil {
		t.Error("an unknown reference resolved")
	}

	// A reference resolves only for the user who added it.
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if a, err := s.bob.ResolveArtifact("sess-1"); err == nil {
		t.Errorf("bob resolved ada's reference to %s", a.ID)
	}
	if a, err := s.bob.ResolveArtifact(s.artifact); err != nil || a.ID != s.artifact {
		t.Errorf("bob resolving the ID: %+v, %v", a, err)
	}

	// Two artifacts on one reference are ambiguous, and the error names both.
	if err := s.ada.AddResource(other.ID, "claude-session", "sess-1"); err != nil {
		t.Fatal(err)
	}
	_, err = s.ada.ResolveArtifact("sess-1")
	if err == nil || !strings.Contains(err.Error(), s.artifact) || !strings.Contains(err.Error(), other.ID) {
		t.Errorf("an ambiguous reference: %v, want both IDs named", err)
	}
}

func TestResolveByNameNamesTheAmbiguousIDs(t *testing.T) {
	c := authedClient(t)
	a, _ := c.CreateArtifact("dup", "")
	b, _ := c.CreateArtifact("dup", "")
	_, err := c.ResolveArtifact("dup")
	if err == nil || !strings.Contains(err.Error(), a.ID) || !strings.Contains(err.Error(), b.ID) {
		t.Errorf("ResolveArtifact(dup) = %v, want both IDs named", err)
	}
}

// A name beats a reference of the same text, and an ID beats both.
func TestResolveOrder(t *testing.T) {
	c := authedClient(t)
	named, _ := c.CreateArtifact("same", "")
	carrier, _ := c.CreateArtifact("carrier", "")
	if err := c.AddResource(carrier.ID, "t", "same"); err != nil {
		t.Fatal(err)
	}
	if a, err := c.ResolveArtifact("same"); err != nil || a.ID != named.ID {
		t.Errorf("ResolveArtifact(same) = %+v, %v, want the artifact named so", a, err)
	}
	if a, err := c.ResolveArtifact(carrier.ID); err != nil || a.ID != carrier.ID {
		t.Errorf("ResolveArtifact(id) = %+v, %v", a, err)
	}
}

// A name that cannot be looked up because the artifact's chain cannot be
// verified, such as a keyring the server rolled back, is not reported as an
// artifact that does not exist: the person is told why.
func TestResolveByNameSaysWhyNamesCouldNotBeRead(t *testing.T) {
	s := newSharing(t)
	if err := s.ada.UpdateArtifact(s.artifact, map[string]string{"name": "findable"}); err != nil {
		t.Fatal(err)
	}
	broken := keyedFor(t, s.host, mustAPIKeyOf(t, s.ada))
	intercept(broken, &tamper{before: func(req *http.Request) *http.Response {
		if req.Method == "GET" && req.URL.Path == "/api/me/keyring" {
			return replyJSON(req, 500, nil, `{"error":"keyring unavailable"}`)
		}
		return nil
	}})
	_, err := broken.ResolveArtifact("findable")
	if err == nil || !strings.Contains(err.Error(), "could not be read") || !strings.Contains(err.Error(), "keyring unavailable") {
		t.Errorf("ResolveArtifact = %v, want the failure named", err)
	}
	// Not "no such artifact": a push --create would make a second one.
	if errors.Is(err, ErrNoArtifact) {
		t.Errorf("ResolveArtifact = %v, which says the artifact does not exist", err)
	}
	// Listing does not fail: the artifact shows under its ID.
	as, err := broken.ListArtifacts()
	if err != nil || len(as) != 1 || as[0].Name != "" || as[0].Title() != s.artifact {
		t.Errorf("ListArtifacts = %+v, %v", as, err)
	}
}
