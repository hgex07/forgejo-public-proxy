// SPDX-License-Identifier: AGPL-3.0-or-later

package gitx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fpp/internal/testutil"
)

func TestParseDiffTree(t *testing.T) {
	out := ":100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb M\x00src/a.go\x00:000000 100644 0000000000000000000000000000000000000000 cccccccccccccccccccccccccccccccccccccccc A\x00bin\x00" +
		"3\t1\tsrc/a.go\x00-\t-\tbin\x00"
	ch, err := parseDiffTree([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(ch) != 2 || string(ch[0].Path) != "src/a.go" || ch[0].Status != 'M' || ch[0].Added != 3 ||
		ch[0].Deleted != 1 || ch[1].Added != -1 || ch[1].Status != 'A' ||
		ch[0].OldOID != strings.Repeat("a", 40) || ch[1].OldMode != "000000" || ch[1].NewMode != "100644" {
		t.Fatalf("%+v", ch)
	}
	for _, bad := range []string{":100644 M\x00a\x00", "1\t2\tunknown\x00", "x\x00", ":1 2 3 4 M", ":100644 100644 aaaa bbbb M\x00a\x00"} {
		if _, err := parseDiffTree([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

const tree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

func TestParseCommit(t *testing.T) {
	raw := "tree " + tree + "\nparent " + tree + "\nparent " + tree +
		"\nauthor Alice <alice@corp.example> 1700000000 +0530\ncommitter Bob <bob@corp.example> 1700003600 -0800\n" +
		"encoding ISO-8859-1\ngpgsig -----BEGIN PGP SIGNATURE-----\n abc\n -----END PGP SIGNATURE-----\n\nsubject\n\nbody\n"
	c, err := ParseCommit([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if c.Tree != tree || len(c.Parents) != 2 || c.Author.Name != "Alice" || c.Committer.Name != "Bob" ||
		c.Author.When.Unix() != 1700000000 || c.Author.When.Location().String() != "UTC" ||
		c.Encoding != "ISO-8859-1" || string(c.Message) != "subject\n\nbody\n" {
		t.Fatalf("%+v", c)
	}
	for _, bad := range []string{
		"", "tree x\n\n", "author A <a> 1 +0000\ncommitter A <a> 1 +0000\n\n",
		"tree " + tree + "\nauthor A a 1\ncommitter A <a> 1 +0000\n\n",
		"tree " + tree + "\nauthor A <a> x +0000\ncommitter A <a> 1 +0000\n\n",
		"tree " + tree + "\n author\n\n",
	} {
		if _, err := ParseCommit([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestParseTag(t *testing.T) {
	raw := "object " + tree + "\ntype commit\ntag v1\ntagger T <t@corp.example> 1700000000 +0000\n\nmsg\n-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----\n"
	tg, err := ParseTag([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tg.Object != tree || tg.Type != "commit" || tg.Name != "v1" || tg.Tagger.Name != "T" || string(tg.Message) != "msg\n" {
		t.Fatalf("%+v", tg)
	}
}

func TestValidRefName(t *testing.T) {
	for s, ok := range map[string]bool{
		"refs/heads/main": true, "refs/fpp/heads/release/2.x": true, "refs/tags/v1.0": true,
		"main": false, "refs/heads/a..b": false, "refs/heads/-x": false, "refs/heads/.x": false,
		"refs/heads/x.lock": false, "refs/heads/a b": false, "refs/heads/a:b": false, "refs/heads/": false,
		"refs/heads/a@{1}": false, "refs//x": false, "refs/heads/x\n": false,
	} {
		if ValidRefName(s) != ok {
			t.Errorf("ValidRefName(%q) != %v", s, ok)
		}
	}
}

func TestSanitizeScrubsAuth(t *testing.T) {
	r := &Repo{auth: "Basic Ym90OnNlY3JldA=="}
	got := r.sanitize("fatal: header Basic Ym90OnNlY3JldA== and Ym90OnNlY3JldA==\x1b[31m")
	if strings.Contains(got, "Ym90") || strings.Contains(got, "\x1b") {
		t.Fatalf("%q", got)
	}
}

func TestOpenRejects(t *testing.T) {
	for _, c := range [][4]string{
		{"/r", "/h", "file:///x", "a"},
		{"/r", "/h", "ssh://h/x", "a"},
		{"/r", "/h", "https://u:p@h/x", "a"},
		{"/r", "/h", "https://h/x", "a\r\nX: y"},
		{"rel", "/h", "https://h/x", "a"},
	} {
		if _, err := Open(c[0], c[1], c[2], c[3]); err == nil {
			t.Errorf("Open%v accepted", c)
		}
	}
}

// The environment must not inherit anything from the caller.
func TestEnvIsolation(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(filepath.Join(dir, "r.git"), filepath.Join(dir, "home"), "https://h/x", "Basic abc")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_PARAMETERS", "'core.hookspath'='/tmp/evil'")
	t.Setenv("GIT_DIR", "/tmp/elsewhere")
	t.Setenv("GIT_SSL_NO_VERIFY", "1")
	ctx := context.Background()
	if err := r.Init(ctx, "sha1"); err != nil {
		t.Fatal(err)
	}
	if err := r.Init(ctx, "sha1"); err != nil {
		t.Fatalf("re-init: %v", err)
	}
	if err := r.Init(ctx, "sha256"); err == nil {
		t.Fatal("object format mismatch accepted")
	}
	out, err := r.run(ctx, runOpts{}, "config", "--list")
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(out)
	if strings.Contains(cfg, "evil") || strings.Contains(cfg, "extraheader") || !strings.Contains(cfg, "core.hookspath=/dev/null") {
		t.Fatalf("local config:\n%s", cfg)
	}
	out, err = r.run(ctx, runOpts{remote: true}, "config", "--get", "http.extraHeader")
	if err != nil || strings.TrimSpace(string(out)) != "Authorization: Basic abc" {
		t.Fatalf("remote header: %q %v", out, err)
	}
	for _, e := range r.env(true) {
		if strings.HasPrefix(e, "GIT_SSL_NO_VERIFY") || strings.HasPrefix(e, "GIT_CONFIG_PARAMETERS") {
			t.Errorf("leaked %s", e)
		}
	}
	attrs, err := os.ReadFile(filepath.Join(r.Dir(), "info", "attributes"))
	if err != nil || !strings.Contains(string(attrs), "-export-subst") {
		t.Errorf("attributes: %q %v", attrs, err)
	}
}

func TestFetchNeverRunsHooksAndHonorsDepth(t *testing.T) {
	srv := testutil.NewGitServer(t, "bot", "pw")
	fx := testutil.NewFixture(t)
	var oids []string
	for i := range 6 {
		fx.Write("f", strings.Repeat("x", i+1))
		oids = append(oids, fx.Commit("c"))
	}
	fx.Publish(srv, "o/r")
	srv.Allow("o/r")

	dir := t.TempDir()
	r, err := Open(filepath.Join(dir, "r.git"), filepath.Join(dir, "home"), srv.RepoURL("o/r"), "Basic Ym90OnB3")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := r.Init(ctx, ""); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "hook-ran")
	hooks := filepath.Join(r.Dir(), "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"reference-transaction", "post-checkout", "post-merge"} {
		if err := os.WriteFile(filepath.Join(hooks, h), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	refs, err := r.LsRemote(ctx)
	if err != nil || len(refs) != 1 || refs[0].Name != "refs/heads/main" || refs[0].OID != oids[5] {
		t.Fatalf("ls-remote %+v %v", refs, err)
	}
	if err := r.Fetch(ctx, []FetchRef{{Remote: "refs/heads/main", Local: "refs/fpp/heads/main"}}, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a hook ran")
	}
	shallow, err := r.Shallow()
	if err != nil || !shallow[oids[3]] || len(shallow) != 1 {
		t.Fatalf("shallow %v %v", shallow, err)
	}
	got, err := r.RevList(ctx, oids[5], 10)
	if err != nil || len(got) != 3 {
		t.Fatalf("rev-list %v %v", got, err)
	}
	if _, err := r.ReadObjects(ctx, []string{oids[2]}, 1<<20); err == nil {
		t.Fatal("object outside the depth was fetched")
	}
	if _, err := r.ReadObjects(ctx, []string{oids[5]}, 10); err == nil {
		t.Fatal("size cap ignored")
	}
	if err := r.Fetch(ctx, []FetchRef{{Remote: "refs/remotes/x", Local: "refs/fpp/x"}}, 1); err == nil {
		t.Fatal("non-branch/tag refspec accepted")
	}
	if err := r.Fetch(ctx, []FetchRef{{Remote: "refs/heads/main", Local: "refs/heads/main"}}, 1); err == nil {
		t.Fatal("local ref outside refs/fpp accepted")
	}

	bad, _ := Open(filepath.Join(dir, "r.git"), filepath.Join(dir, "home"), srv.RepoURL("o/r"), "Basic d3Jvbmc=")
	if _, err := bad.LsRemote(ctx); err == nil {
		t.Fatal("wrong credentials accepted")
	} else if strings.Contains(err.Error(), "d3Jvbmc=") {
		t.Fatal("error leaks the credential")
	}
	if err := r.ProbeHidden(ctx, srv.RepoURL("o/missing")); err != nil {
		t.Fatalf("missing repo probe: %v", err)
	}
	if err := r.ProbeHidden(ctx, srv.RepoURL("o/r")); err == nil {
		t.Fatal("readable repo passed the probe")
	}
	if err := r.ProbeHidden(ctx, "http://other.example/o/r.git"); err == nil {
		t.Fatal("probe to another host accepted")
	}
}

// Parsers see bytes from repos we don't control: they must never panic.
func FuzzParsers(f *testing.F) {
	f.Add([]byte("tree " + tree + "\nauthor A <a> 1 +0000\ncommitter A <a> 1 +0000\n\nm"))
	f.Add([]byte("object " + tree + "\ntype commit\n\n-----BEGIN PGP SIGNATURE-----"))
	f.Add([]byte(":100644 100644 a b M\x00p\x001\t2\tp\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseCommit(b)
		ParseTag(b)
		parseDiffTree(b)
	})
}
