// SPDX-License-Identifier: AGPL-3.0-or-later

package gates

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fpp/internal/config"
	"fpp/internal/forgejo"
	"fpp/internal/policy"
	"fpp/internal/testutil"
)

// Planted secrets are assembled at run time so this file itself never
// trips a secret scanner (fpp publishes its own source).
var (
	githubPAT = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
	awsKey    = "AKIA" + "IOSFODNN7EXAMPLQ"
)

const planted = "tok-gates-0123456789"

const gatesConfig = `
site: {title: t, base_url: "https://code.example.com", theme: a, robots: index}
forgejo:
  api_url: "http://127.0.0.1:3000"
  root_url: "https://Forgejo.LAN"
  user: bot
  token: {credential: tok}
  canary_repos: ["x/canary-private", "x/canary-public"]
gates:
  public_emails: ["press@example.org"]
  leak_patterns:
    - {pattern: '\b172\.16\.\d{1,3}\.\d{1,3}\b', action: warn}
    - {pattern: 'codename-[a-z]+', action: block}
publish:
  repos:
    - source: "me/proj"
      diffs: DIFFS
deploy: {target: "deploy@10.0.0.1", ssh_key: {credential: k}, known_hosts: "/etc/fpp/kh"}
`

type world struct {
	cfg *config.Config
	set *policy.Set
}

func hostile(t *testing.T, diffs bool) *world {
	t.Helper()
	srv := testutil.NewGitServer(t, "bot", planted)
	fx := testutil.NewFixture(t)
	fx.Write("aws.txt", "key = "+awsKey+"\n")
	fx.Write("README.md", "# hi\n")
	fx.Commit("first")
	if err := os.Remove(filepath.Join(fx.Dir, "aws.txt")); err != nil {
		t.Fatal(err)
	}
	fx.Write("README.md", "# hi\n\nSee https://forgejo.lan/me/proj or the box at 172.16.0.20.\n")
	fx.Write("cfg/gh.env.example", "GITHUB_TOKEN="+githubPAT+"\n")
	fx.Write("trojan.go", "package x\n// \u202e evil\n")
	fx.Write("notes/codename-falcon.md", "plans\n")
	// gitleaks default config skips these paths; fpp publishes them.
	fx.Write("node_modules/sdk/config.js", "module.exports = {token: \""+githubPAT+"\"}\n")
	fx.Write("web/bootstrap.prod.js", "var t = \""+githubPAT+"\";\n")
	// Not UTF-8 (Latin-1 comment) and binary: still published, so scanned.
	fx.Write("legacy.properties", "# caf\xe9\ngithub.token="+githubPAT+"\n")
	fx.Write("blob.bin", "\x00\x01bin "+githubPAT+"\x00\n")
	fx.Commit("remove key, planted " + planted + "\n\nCo-authored-by: Carol <carol@secret-corp.example>\nSigned-off-by: Press <press@example.org>\nContact dave@secret-corp.example.")
	fx.Publish(srv, "me/proj")
	srv.Allow("me/proj")
	api := &testutil.FakeAPI{Srv: srv, Repos: map[string]*forgejo.Repo{"me/proj": {
		FullName: "me/proj", DefaultBranch: "main", ObjectFormat: "sha1",
		Description: "mail ops@secret-corp.example",
	}}}
	d := "false"
	if diffs {
		d = "true"
	}
	cfg, _, err := config.Parse([]byte(strings.Replace(gatesConfig, "DIFFS", d, 1)))
	if err != nil {
		t.Fatal(err)
	}
	set, err := (&policy.Builder{Config: cfg, API: api, StateDir: t.TempDir()}).Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return &world{cfg: cfg, set: set}
}

func run(t *testing.T, w *world, baseline map[string]string) *Report {
	t.Helper()
	rep, err := Run(context.Background(), w.set, Options{Config: w.cfg, Token: planted, Baseline: baseline})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func find(rep *Report, rule, where string) *Finding {
	for i, f := range rep.Findings {
		if f.Rule == rule && strings.Contains(f.Where, where) {
			return &rep.Findings[i]
		}
	}
	return nil
}

func TestGatesHostileFixture(t *testing.T) {
	w := hostile(t, true)
	rep := run(t, w, nil)
	for _, f := range rep.Findings {
		t.Logf("%s %s %s %s %s", f.Action, f.Rule, f.Where, f.Excerpt, f.Fingerprint)
		if strings.Contains(f.Excerpt, planted) || strings.Contains(f.Excerpt, githubPAT) || strings.Contains(f.Excerpt, awsKey) {
			t.Errorf("finding shows a secret: %+v", f)
		}
	}
	cases := []struct {
		rule, where string
		action      Action
	}{
		{RuleForgejoHost, "main:README.md:3", Block},
		{"leak_patterns[0]", "main:README.md:3", Warn},
		{"secret:github-pat", "main:cfg/gh.env.example:1", Block},
		{"secret:github-pat", "main:node_modules/sdk/config.js:1", Block},
		{"secret:github-pat", "main:web/bootstrap.prod.js:1", Block},
		{"secret:github-pat", "main:legacy.properties:2", Block},
		{"secret:github-pat", "main:blob.bin", Block},
		{"secret:aws-access-token", "diff aws.txt", Block}, // only in a removed line
		{RuleToken, "message", Block},
		{"leak_patterns[1]", "path notes/codename-falcon.md", Block},
		{RuleBidi, "main:trojan.go", Warn},
	}
	for _, c := range cases {
		f := find(rep, c.rule, c.where)
		if f == nil {
			t.Errorf("missing %s at %s", c.rule, c.where)
			continue
		}
		if f.Action != c.action {
			t.Errorf("%s at %s: action %s, want %s", c.rule, c.where, f.Action, c.action)
		}
	}
	if len(rep.Blocked()) == 0 {
		t.Fatal("hostile fixture not blocked")
	}

	// Redaction happened in place, before scanning.
	if rep.Redacted != 3 { // carol, dave, ops; press is public
		t.Errorf("redacted %d addresses, want 3", rep.Redacted)
	}
	for _, c := range w.set.Repos[0].Commits {
		if strings.Contains(c.Message, "secret-corp") {
			t.Errorf("email left in message: %q", c.Message)
		}
		if strings.Contains(c.Message, "Co-authored-by") && !strings.Contains(c.Message, "Co-authored-by: Carol\n") {
			t.Errorf("trailer not cleaned: %q", c.Message)
		}
		if strings.Contains(c.Message, "Signed-off-by") && !strings.Contains(c.Message, "<press@example.org>") {
			t.Errorf("public email removed: %q", c.Message)
		}
	}
	if d := w.set.Repos[0].Meta.Description; d != "mail [email]" {
		t.Errorf("description %q", d)
	}

	// The baseline downgrades a reviewed secret-scan finding, nothing else.
	gh := find(rep, "secret:github-pat", "gh.env")
	rep2 := run(t, hostile(t, true), map[string]string{gh.Fingerprint: "example file", "0000000000000000": "unused"})
	if f := find(rep2, "secret:github-pat", "gh.env"); f == nil || f.Action != Warn || f.Baselined != "example file" {
		t.Errorf("baselined finding: %+v", f)
	}
	if find(rep2, RuleForgejoHost, "README").Action != Block {
		t.Error("baseline affected a host finding")
	}
}

func TestGatesDiffsOff(t *testing.T) {
	// Without diffs the removed line is never published, so not scanned.
	rep := run(t, hostile(t, false), nil)
	if f := find(rep, "secret:aws-access-token", ""); f != nil {
		t.Errorf("scanned an unpublished diff: %+v", f)
	}
	if find(rep, "secret:github-pat", "gh.env") == nil {
		t.Error("tree secret not found")
	}
}

func TestGatesSecretScanOff(t *testing.T) {
	w := hostile(t, false)
	off := false
	w.cfg.Gates.SecretScan.Enabled = &off
	rep := run(t, w, nil)
	if rep.SecretScan || find(rep, "secret:github-pat", "") != nil {
		t.Error("secret scan ran while disabled")
	}
	if find(rep, RuleForgejoHost, "README") == nil || find(rep, RuleToken, "") == nil {
		t.Error("built-in leak rules must run even with the secret scan off")
	}
}

func TestMatcherHosts(t *testing.T) {
	cfg := &config.Config{Forgejo: config.Forgejo{RootURL: "https://Git.Example.LAN:8443", APIURL: "http://127.0.0.1:3000"}}
	m, err := NewMatcher(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	for s, want := range map[string]bool{
		"git.example.lan":                true,
		"https://GIT.example.lan/x":      true,
		"ci.git.example.lan":             true, // subdomain leaks the same name
		"(git.example.lan)":              true,
		"git.example.lan.":               true,
		"mygit.example.lan":              false,
		"git.example.land":               false,
		"git-example-lan":                false,
		"127.0.0.1:3000 is fine":         false,
		"module git.example.lan/foo/bar": true,
	} {
		if _, got := m.Blocks([]byte(s)); got != want {
			t.Errorf("%q: blocks=%t, want %t", s, got, want)
		}
	}
	if hs := ForgejoHosts(cfg); len(hs) != 1 || hs[0] != "git.example.lan" {
		t.Errorf("hosts %v", hs)
	}
}

func TestRedactText(t *testing.T) {
	r := NewRedactor([]string{"Press@Example.org"})
	for in, want := range map[string]string{
		"Co-authored-by: A B <a.b+x@mail.example.com>": "Co-authored-by: A B",
		"Signed-off-by: P <press@example.org>":         "Signed-off-by: P <press@example.org>",
		"mail me: x_y@sub.example.co.uk.":              "mail me: [email].",
		"see <a@b.io> and c@d.io":                      "see and [email]",
		"git@github.com:foo/bar.git":                   "[email]:foo/bar.git",
		"user@localhost stays":                         "user@localhost stays",
		"no email here @ all":                          "no email here @ all",
	} {
		if got, _ := r.Text(in); got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzRedact(f *testing.F) {
	for _, s := range []string{"a <b@c.d>", "x@y.z", "<<a@b.c>>", "a@b.c@d.e", " < x@y.zz > "} {
		f.Add(s)
	}
	r := NewRedactor(nil)
	f.Fuzz(func(t *testing.T, s string) {
		out, _ := r.Text(s)
		if emailRe.MatchString(out) {
			t.Fatalf("Text(%q) = %q still contains an address", s, out)
		}
		if again, n := r.Text(out); again != out || n != 0 {
			t.Fatalf("not idempotent: %q → %q → %q", s, out, again)
		}
	})
}

func TestLoadBaseline(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "b.json")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if m, err := LoadBaseline(write(`{"ignore":[{"fingerprint":"0123456789abcdef","reason":"fixture"}]}`)); err != nil || m["0123456789abcdef"] != "fixture" {
		t.Errorf("valid baseline: %v %v", m, err)
	}
	for _, bad := range []string{
		`{"ignore":[{"fingerprint":"0123456789abcdef"}]}`,
		`{"ignore":[{"fingerprint":"XYZ","reason":"r"}]}`,
		`{"ignore":[],"extra":1}`,
		`{"ignore":[]} {}`,
	} {
		if _, err := LoadBaseline(write(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := LoadBaseline(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing configured baseline accepted")
	}
}
