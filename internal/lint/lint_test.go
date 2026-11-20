// SPDX-License-Identifier: AGPL-3.0-or-later

package lint

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fpp/internal/config"
	"fpp/internal/forgejo"
	"fpp/internal/gates"
	"fpp/internal/policy"
	"fpp/internal/site"
	"fpp/internal/testutil"
)

const planted = "tok-lint-0123456789"

const lintConfig = `
site: {title: t, base_url: "https://code.example.com", theme: a, robots: index}
forgejo:
  api_url: "http://127.0.0.1:3000"
  root_url: "https://forgejo.lan"
  user: bot
  token: {credential: tok}
  canary_repos: ["x/canary-private", "x/canary-public"]
gates:
  leak_patterns: [{pattern: 'codename-[a-z]+', action: block}, {pattern: '10\.\d+\.\d+\.\d+', action: warn}]
publish:
  repos: [{source: "me/proj", diffs: true}]
deploy: {target: "deploy@10.0.0.1", ssh_key: {credential: k}, known_hosts: "/etc/fpp/kh"}
`

type staged struct {
	opts Options
	dir  string
}

// stage generates a site from files (path → content) without running the
// gates, so the lint is tested on its own.
func stage(t *testing.T, files map[string]string, msg string) *staged {
	t.Helper()
	srv := testutil.NewGitServer(t, "bot", planted)
	fx := testutil.NewFixture(t)
	for p, c := range files {
		fx.Write(p, c)
	}
	fx.Commit(msg)
	fx.Publish(srv, "me/proj")
	srv.Allow("me/proj")
	api := &testutil.FakeAPI{Srv: srv, Repos: map[string]*forgejo.Repo{"me/proj": {
		FullName: "me/proj", DefaultBranch: "main", ObjectFormat: "sha1"}}}
	cfg, _, err := config.Parse([]byte(lintConfig))
	if err != nil {
		t.Fatal(err)
	}
	set, err := (&policy.Builder{Config: cfg, API: api, StateDir: t.TempDir()}).Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "site")
	res, err := site.Generate(context.Background(), site.Options{Config: cfg, Set: set, Out: dir, CloneWork: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	m, err := gates.NewMatcher(cfg, planted)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.EffectiveLimits()
	return &staged{dir: dir, opts: Options{Dir: dir, Matcher: m, Written: res.Written, Set: set,
		MaxBytes: l.MaxSiteBytes, MaxFileBytes: l.RawMaxBytes, Work: t.TempDir()}}
}

func (s *staged) lint(t *testing.T) []Problem {
	t.Helper()
	probs, err := Site(context.Background(), s.opts)
	if err != nil {
		t.Fatal(err)
	}
	return probs
}

func has(probs []Problem, path, msg string) bool {
	for _, p := range probs {
		if strings.Contains(p.Path, path) && strings.Contains(p.Msg, msg) {
			return true
		}
	}
	return false
}

var clean = map[string]string{
	"README.md":   "# Clean\n\n- [x] done\n- [ ] todo\n\n<details><summary>s</summary>x</details>\n",
	"src/main.go": "package main\n\n// see 10.1.2.3 (warn only)\nfunc main() {}\n",
	"logo.svg":    `<svg xmlns="http://www.w3.org/2000/svg"></svg>`,
}

func TestCleanSitePasses(t *testing.T) {
	s := stage(t, clean, "first")
	if probs := s.lint(t); len(probs) != 0 {
		t.Fatalf("clean site has problems:\n%v", probs)
	}
}

func TestBlockedValuesEverywhere(t *testing.T) {
	// The gates would stop this; the lint must catch it on its own, in
	// every form the content is published in.
	s := stage(t, map[string]string{
		"README.md":            "Internal: https://forgejo.lan/me/proj\n",
		"notes.txt":            "t=" + planted + "\n",
		"codename-falcon/x.md": "x\n",
	}, "init")
	probs := s.lint(t)
	for _, want := range [][2]string{
		{"me/proj/raw/main/README.md", "forgejo-host"},
		{"me/proj/raw/main/notes.txt", "token"},
		{"me/proj/blob/main/notes.txt/index.html", "token"},
		{"me/proj/archive/main.zip!proj-main/notes.txt", "token"},
		{"me/proj/archive/main.tar.gz!proj-main/notes.txt", "token"},
		{"me/proj/archive/main.zip!proj-main/codename-falcon/x.md", "leak_patterns[0]"},
		{"me/proj.git", "blob object"},
		{"me/proj.git", "tree object"}, // the path lives in a tree object
		{"me/proj/tree/main/codename-falcon/index.html", "leak_patterns[0]"},
		{"me/proj/raw/main/codename-falcon/x.md (path)", "leak_patterns[0]"},
	} {
		if !has(probs, want[0], want[1]) {
			t.Errorf("no problem %q at %s\n%v", want[1], want[0], probs)
		}
	}
	for _, p := range probs {
		if strings.Contains(p.String(), planted) {
			t.Fatalf("problem shows the token: %s", p)
		}
	}
}

func TestTampering(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(t *testing.T, dir string)
		path   string
		msg    string
	}{
		{"stray file", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "me/proj/extra.html"), "<p>x</p>")
		}, "me/proj/extra.html", "not written by the generator"},
		{"missing file", func(t *testing.T, dir string) {
			rm(t, filepath.Join(dir, "robots.txt"))
		}, "robots.txt", "missing"},
		{"symlink", func(t *testing.T, dir string) {
			if err := os.Symlink("/etc/passwd", filepath.Join(dir, "me/proj/passwd")); err != nil {
				t.Fatal(err)
			}
		}, "me/proj/passwd", "not a regular file"},
		{"mode", func(t *testing.T, dir string) {
			if err := os.Chmod(filepath.Join(dir, "robots.txt"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "robots.txt", "file mode"},
		{"unpublished bytes", func(t *testing.T, dir string) {
			rm(t, filepath.Join(dir, "me/proj/raw/main/README.md"))
			write(t, filepath.Join(dir, "me/proj/raw/main/.env"), "x")
		}, "me/proj/raw/main/.env", "no published file"},
		{"foreign repo", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "other/repo/index.html"), "<p>x</p>")
		}, "other/repo/index.html", "unpublished repo"},
		{"entity-encoded host", func(t *testing.T, dir string) {
			appendTo(t, filepath.Join(dir, "index.html"), "<p>forgejo&#46;lan</p>")
		}, "index.html (decoded)", "forgejo-host"},
		{"inline script", func(t *testing.T, dir string) {
			appendTo(t, filepath.Join(dir, "index.html"), "<script>alert(1)</script>")
		}, "index.html", "<script> element"},
		{"event handler", func(t *testing.T, dir string) {
			appendTo(t, filepath.Join(dir, "index.html"), `<img src="/x.png" OnError="x()">`)
		}, "index.html", "event handler"},
		{"style attribute", func(t *testing.T, dir string) {
			appendTo(t, filepath.Join(dir, "index.html"), `<p style="color:red">x</p>`)
		}, "index.html", "style attribute"},
		{"javascript URL", func(t *testing.T, dir string) {
			appendTo(t, filepath.Join(dir, "index.html"), "<a href=\" java\tscript:x()\">x</a>")
		}, "index.html", "dangerous URL"},
		{"iframe", func(t *testing.T, dir string) {
			appendTo(t, filepath.Join(dir, "index.html"), `<iframe src="/"></iframe>`)
		}, "index.html", "forbidden element"},
		{"meta refresh", func(t *testing.T, dir string) {
			appendTo(t, filepath.Join(dir, "index.html"), `<meta http-equiv="refresh" content="0;url=https://evil">`)
		}, "index.html", "http-equiv"},
		{"stray clone file", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "me/proj.git/config"), "[core]\n")
		}, "me/proj.git/config", "unexpected file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := stage(t, clean, "first")
			c.tamper(t, s.dir)
			// Tampered files are not in Written, except for appends.
			probs := s.lint(t)
			if !has(probs, c.path, c.msg) {
				t.Errorf("no %q problem at %s; got %v", c.msg, c.path, probs)
			}
		})
	}
}

func TestQuota(t *testing.T) {
	s := stage(t, clean, "first")
	s.opts.MaxBytes = 1000
	if !has(s.lint(t), ".", "over max_site_bytes") {
		t.Error("quota not enforced")
	}
}

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendTo(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func rm(t *testing.T, p string) {
	t.Helper()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
}
