package client

import "testing"

// putData pushes a version as c and writes a database and a file to it.
func putData(t *testing.T, c *Client, artifact string) {
	t.Helper()
	v, err := c.Push(artifact, "", siteDir(t), "v1", "")
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.OpenData(artifact, v.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutRevision([]byte("db"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutFile("f.txt", []byte("file")); err != nil {
		t.Fatal(err)
	}
}

func TestTeamNoneResealsTheData(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	putData(t, w.ada, w.artifact)
	if _, err := w.bob.Approve(w.artifact, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	res, err := w.ada.Team(w.artifact, "none")
	if err != nil || !res.NewEpoch {
		t.Fatalf("Team none = %+v, %v, want a new epoch", res, err)
	}
	if res.ResealErr != nil || res.Resealed == nil || res.Resealed.Databases != 1 || res.Resealed.Files != 1 {
		t.Fatalf("Resealed = %+v, %v", res.Resealed, res.ResealErr)
	}
}

func TestTransferDroppingThePreviousOwnerResealsTheData(t *testing.T) {
	x := newXfer(t, nil)
	putData(t, x.ada, x.artifact)
	x.offer(x.ada, "bob")
	res, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{DropPreviousOwner: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.ResealErr != nil || res.Resealed == nil || res.Resealed.Databases != 1 || res.Resealed.Files != 1 {
		t.Fatalf("Resealed = %+v, %v: the new owner seals what the previous owner wrote", res.Resealed, res.ResealErr)
	}
	d, err := x.bob.OpenData(x.artifact, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if plain, _, err := d.Latest(); err != nil || string(plain) != "db" {
		t.Errorf("Latest = %q, %v", plain, err)
	}
	if got, err := d.GetFile("f.txt"); err != nil || string(got) != "file" {
		t.Errorf("GetFile = %q, %v", got, err)
	}
}
