// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fpp/internal/testutil"
)

type e2e struct {
	gs    *testutil.GitServer
	fx    *testutil.Fixture
	dir   string
	cfg   string
	state string
}

// newE2E starts a fake Forgejo (API + real git smart HTTP) serving one repo
// and writes a config and credentials for it.
func newE2E(t *testing.T) *e2e {
	t.Helper()
	gs := testutil.NewGitServer(t, "bot", "tok-e2e")
	fx := testutil.NewFixture(t)
	fx.Write("README.md", "# hi\n")
	fx.Write(".env", "SECRET=1\n")
	fx.Commit("init")
	fx.Publish(gs, "me/proj")
	gs.Allow("me/proj")

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token tok-e2e" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/v1/repos/me/proj":
			fmt.Fprint(w, `{"full_name":"me/proj","default_branch":"main","description":"demo","object_format_name":"sha1"}`)
		case "/api/v1/repos/search":
			fmt.Fprint(w, `{"ok":true,"data":[{"full_name":"me/proj"}]}`)
		case "/api/v1/user":
			w.WriteHeader(403)
		default:
			w.WriteHeader(404)
		}
	})
	mux.Handle("/", gs.Config.Handler)
	forge := httptest.NewServer(mux)
	t.Cleanup(forge.Close)

	dir := t.TempDir()
	creds := filepath.Join(dir, "creds")
	if err := os.Mkdir(creds, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(creds, "tok"), []byte("tok-e2e\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", creds)
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte(`
site: {title: t, base_url: "https://code.example.com", theme: a, robots: noindex}
forgejo:
  api_url: "`+forge.URL+`"
  root_url: "https://forgejo.lan"
  user: bot
  token: {credential: tok}
  canary_repos: ["x/canary-private", "x/canary-public"]
publish:
  repos: [{source: "me/proj"}]
deploy: {target: "deploy@10.0.0.1", ssh_key: {credential: k}, known_hosts: "/etc/fpp/kh"}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	return &e2e{gs: gs, fx: fx, dir: dir, cfg: cfg, state: filepath.Join(dir, "state")}
}

// TestPlanEndToEnd runs `fpp plan` against a fake Forgejo and checks the
// report and the diff against a published manifest.
func TestPlanEndToEnd(t *testing.T) {
	e := newE2E(t)
	gs, fx, dir, cfg, state := e.gs, e.fx, e.dir, e.cfg, e.state
	planOnce := func() string {
		t.Helper()
		var out, errb bytes.Buffer
		code := run([]string{"plan", "-config", cfg, "-state", state, "-manifest-out", filepath.Join(dir, "m.json")}, &out, &errb)
		if code != exitOK {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		if strings.Contains(out.String()+errb.String(), "tok-e2e") {
			t.Fatal("token in output")
		}
		return out.String()
	}

	first := planOnce()
	for _, want := range []string{"access checks: OK", "me/proj → /me/proj/", "branch main", "1 files",
		"excluded (1)", ".env", "NEW: first publish", "README.md"} {
		if !strings.Contains(first, want) {
			t.Errorf("first plan lacks %q:\n%s", want, first)
		}
	}

	// Pretend it was applied, then change the repo.
	if err := os.MkdirAll(filepath.Join(state, "published"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "m.json"), publishedManifest(state)); err != nil {
		t.Fatal(err)
	}
	if got := planOnce(); !strings.Contains(got, "no changes") {
		t.Errorf("unchanged repo:\n%s", got)
	}
	fx.Write("NEW.md", "new\n")
	fx.Commit("add")
	fx.Publish(gs, "me/proj")
	second := planOnce()
	for _, want := range []string{"~ me/proj", "+ becomes public (1)", "NEW.md", "+ 1 commits"} {
		if !strings.Contains(second, want) {
			t.Errorf("second plan lacks %q:\n%s", want, second)
		}
	}
	if gs.PushAttempts() != 3 {
		t.Errorf("push probes: %d, want one per plan", gs.PushAttempts())
	}
}

func TestPreviewBuildOnly(t *testing.T) {
	e := newE2E(t)
	out := filepath.Join(e.dir, "site")
	var stdout, stderr bytes.Buffer
	args := []string{"preview", "-config", e.cfg, "-state", e.state, "-out", out, "-build-only"}
	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "site: ") {
		t.Errorf("stdout: %s", stdout.String())
	}
	home, err := os.ReadFile(filepath.Join(out, "me", "proj", "index.html"))
	if err != nil || !strings.Contains(string(home), "demo") {
		t.Fatalf("repo home: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "me", "proj", "raw", "main", ".env")); err == nil {
		t.Error(".env published")
	}
	// A rebuild replaces the previous build...
	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("rebuild exit %d: %s", code, stderr.String())
	}
	// ...but never a directory fpp did not create.
	foreign := filepath.Join(e.dir, "foreign")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	args[6] = foreign
	if code := run(args, &stdout, &stderr); code == exitOK || !strings.Contains(stderr.String(), "refusing") {
		t.Fatalf("replaced a foreign directory: exit %d %s", code, stderr.String())
	}
	if code := run([]string{"preview", "-site", out, "-addr", "0.0.0.0:0"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("non-loopback addr: exit %d", code)
	}
}
