// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"fpp/internal/policy"
)

func set(files map[string]string, commits ...string) *policy.Set {
	ref := &policy.Ref{Kind: policy.Branch, Name: "main", Public: "main", Commit: "c-" + commits[0]}
	for p, oid := range files {
		ref.Files = append(ref.Files, policy.File{Path: p, Kind: policy.Regular, OID: oid, Size: 1})
	}
	r := &policy.Repo{Source: "me/proj", Slug: "pub/proj", Refs: []*policy.Ref{ref}, Commits: map[string]*policy.Commit{}}
	for _, c := range commits {
		r.Commits[c] = &policy.Commit{OID: c}
	}
	return &policy.Set{Repos: []*policy.Repo{r}}
}

func TestCompare(t *testing.T) {
	old := FromSet(set(map[string]string{"a": "1", "b": "2", "c": "3"}, "x", "y"))
	cur := FromSet(set(map[string]string{"a": "1", "b": "9", "d": "4"}, "z", "x"))
	d := Compare(old, cur)
	if len(d.Repos) != 1 {
		t.Fatalf("%+v", d)
	}
	r := d.Repos[0]
	if r.New || !slices.Equal(r.PathsAdded, []string{"d"}) || !slices.Equal(r.PathsChanged, []string{"b"}) ||
		!slices.Equal(r.PathsRemoved, []string{"c"}) || r.CommitsAdded != 1 || !slices.Equal(r.RefsMoved, []string{"main"}) {
		t.Errorf("%+v", r)
	}
	if !Compare(cur, cur).Empty() {
		t.Error("self-diff not empty")
	}
	first := Compare(nil, cur)
	if !slices.Equal(first.NewRepos(), []string{"pub/proj"}) || len(first.Repos[0].PathsAdded) != 3 {
		t.Errorf("first publish %+v", first)
	}
	gone := Compare(cur, FromSet(&policy.Set{}))
	if !gone.Repos[0].Removed || len(gone.Repos[0].PathsRemoved) != 3 {
		t.Errorf("removal %+v", gone)
	}
}

func TestReadWrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "m.json")
	if m, err := Read(p); m != nil || err != nil {
		t.Fatalf("missing: %v %v", m, err)
	}
	m := FromSet(set(map[string]string{"a": "1"}, "x"))
	if err := Write(p, m); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	got, err := Read(p)
	if err != nil || !Compare(m, got).Empty() {
		t.Fatalf("round trip: %v", err)
	}
	if err := os.WriteFile(p, []byte(`{"version":1,"repos":{},"extra":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p); err == nil {
		t.Error("unknown field accepted")
	}
	if err := os.WriteFile(p, []byte(`{"version":2,"repos":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p); err == nil {
		t.Error("wrong version accepted")
	}
}

func TestCompareSourceSwap(t *testing.T) {
	old := FromSet(set(map[string]string{"a": "1"}, "x"))
	cur := FromSet(set(map[string]string{"a": "1"}, "x"))
	cur.Repos["pub/proj"].Source = "me/internal" // same slug, different repo
	if got := Compare(old, cur).NewRepos(); !slices.Equal(got, []string{"pub/proj"}) {
		t.Errorf("source swap behind a published slug: new repos %v, want [pub/proj]", got)
	}
	cur.Repos["pub/proj"].Source = "Me/Proj" // Forgejo names are case-insensitive
	if !Compare(old, cur).Empty() {
		t.Error("a case-only source change counted as a new repo")
	}
}
