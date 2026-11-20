// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"strings"
	"testing"
)

const base = `
site:
  title: t
  base_url: https://code.example.com
forgejo:
  api_url: http://127.0.0.1:3000
  root_url: https://forgejo.lan
  user: bot
  token: { credential: forgejo-token }
  canary_repos: [me/canary-private, me/canary-public]
publish:
  repos:
    - source: me/one
deploy:
  target: deploy@10.0.0.1
  ssh_key: { credential: deploy-key }
  known_hosts: /etc/fpp/known_hosts
`

func mustParse(t *testing.T, doc string) (*Config, []string) {
	t.Helper()
	cfg, warns, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return cfg, warns
}

func TestExampleConfigValidates(t *testing.T) {
	cfg, _, err := Load("../../deploy/builder/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Effective(1).Slug; got != "tools/homelab" {
		t.Errorf("slug = %q", got)
	}
}

func TestSecureDefaults(t *testing.T) {
	cfg, warns := mustParse(t, base)
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
	e := cfg.Effective(0)
	if e.Slug != "me/one" || e.MaxCommits != 10 || e.Diffs || e.Releases || e.Assets ||
		len(e.TagInclude) != 0 || !e.Archives || e.Authors != "names" || e.Dates != "day" {
		t.Errorf("defaults not secure: %+v", e)
	}
	if len(e.Branches) != 1 || e.Branches[0].Name != DefaultBranch {
		t.Errorf("branches = %+v", e.Branches)
	}
	if !cfg.SecretScanEnabled() || cfg.KeepReleases() != 5 {
		t.Error("secret scan must default on, keep_releases to 5")
	}
	if cfg.EffectiveLimits() != DefaultLimits {
		t.Errorf("limits = %+v", cfg.EffectiveLimits())
	}
}

func TestExcludeIsAdditive(t *testing.T) {
	doc := strings.Replace(base, "publish:\n", "publish:\n  defaults: { exclude: [\"secret/**\"] }\n", 1)
	doc = strings.Replace(doc, "- source: me/one", "- source: me/one\n      exclude: [\"*.bak\"]", 1)
	cfg, _ := mustParse(t, doc)
	ex := cfg.Effective(0).Exclude
	want := append(append([]string{}, BuiltinExclude...), "secret/**", "*.bak")
	if strings.Join(ex, " ") != strings.Join(want, " ") {
		t.Errorf("exclude = %v", ex)
	}
}

func TestPartialOverride(t *testing.T) {
	doc := strings.Replace(base, "publish:\n", "publish:\n  defaults: { releases: { prereleases: true }, history: { max_commits: 3 } }\n", 1)
	doc = strings.Replace(doc, "- source: me/one", "- source: me/one\n      releases: { enabled: true }", 1)
	cfg, _ := mustParse(t, doc)
	e := cfg.Effective(0)
	if !e.Releases || !e.Prereleases || e.Assets || e.MaxCommits != 3 {
		t.Errorf("override merge wrong: %+v", e)
	}
}

func TestInvalid(t *testing.T) {
	repo := func(extra string) string {
		return strings.Replace(base, "- source: me/one", "- source: me/one\n      "+extra, 1)
	}
	cases := []struct {
		name, doc, want string
	}{
		{"unknown key", base + "extra: 1\n", "field extra not found"},
		{"unknown nested key", repo("diff: true"), "field diff not found"},
		{"duplicate key", base + "site: {}\n", "already defined"},
		{"two documents", base + "---\n" + base, "exactly one YAML document"},
		{"empty", "", "empty"},
		{"inline token", strings.Replace(base, "token: { credential: forgejo-token }", "token: abc123", 1), "decode"},
		{"credential path", strings.Replace(base, "credential: forgejo-token", "credential: /etc/token", 1), "credential name"},
		{"http base_url", strings.Replace(base, "https://code.example.com", "http://code.example.com", 1), "https"},
		{"base_url path", strings.Replace(base, "https://code.example.com", "https://code.example.com/x", 1), "path"},
		{"userinfo in api_url", strings.Replace(base, "http://127.0.0.1:3000", "http://bot:tok@127.0.0.1:3000", 1), "credentials"},
		{"public host is forgejo", strings.Replace(base, "https://forgejo.lan", "https://code.example.com", 1), "must differ"},
		{"no canaries", strings.Replace(base, "canary_repos: [me/canary-private, me/canary-public]", "canary_repos: []", 1), "canary repo is required"},
		{"canary published", strings.Replace(base, "- source: me/one", "- source: me/Canary-Private", 1), "canaries must never be published"},
		{"duplicate source", strings.Replace(base, "- source: me/one", "- source: me/one\n    - source: ME/one", 1), "already listed"},
		{"slug collision", strings.Replace(base, "- source: me/one", "- source: me/one\n    - source: me/two\n      slug: Me/One", 1), "collides"},
		{"reserved slug", repo("slug: _static/x"), "reserved"},
		{"traversal source", strings.Replace(base, "- source: me/one", "- source: ../one", 1), "must match"},
		{"three segments", strings.Replace(base, "- source: me/one", "- source: a/b/c", 1), "owner/repo"},
		{"slash ref without alias", repo(`branches: ["feature/x"]`), "need an alias"},
		{"bad ref", repo(`branches: ["a..b"]`), "not a valid branch"},
		{"option-like ref", repo(`branches: ["-x"]`), "not a valid branch"},
		{"bad alias", repo(`branches: [{name: "feature/x", as: "a/b"}]`), ".as"},
		{"unknown ref key", repo(`branches: [{name: x, alias: y}]`), "allowed: name, as"},
		{"duplicate public ref", repo(`branches: [main, {name: "x/main", as: main}]`), "used twice"},
		{"no refs", repo(`branches: []`), "publishes no refs"},
		{"tags unbounded", repo(`tags: { include: ["v*"] }`), "must be ≥1"},
		{"tag glob with slash", repo(`tags: { include: ["a/*"], latest: 1 }`), "invalid glob"},
		{"max_commits too big", repo(`history: { max_commits: 5000 }`), "between 0 and"},
		{"negative commits", repo(`history: { max_commits: -1 }`), "between 0 and"},
		{"authors", repo(`authors: emails`), "names or hidden"},
		{"dates", repo(`dates: hour`), "day or exact"},
		{"bad exclude", repo(`exclude: ["[a"]`), "invalid glob"},
		{"absolute exclude", repo(`exclude: ["/etc/*"]`), "invalid glob"},
		{"diffs without scan", repo("diffs: true") + "gates: { secret_scan: { enabled: false } }\n", "diffs require"},
		{"bad leak regex", base + "gates: { leak_patterns: [{ pattern: '(', action: block }] }\n", "pattern"},
		{"bad leak action", base + "gates: { leak_patterns: [{ pattern: 'x', action: drop }] }\n", "block or warn"},
		{"relative baseline", base + "gates: { secret_scan: { baseline: x.json } }\n", "absolute"},
		{"limits order", base + "gates: { limits: { render_max_bytes: 100, raw_max_bytes: 10 } }\n", "raw_max_bytes"},
		{"negative limit", base + "gates: { limits: { max_files_per_ref: -1 } }\n", "negative"},
		{"bad duration", base + "gates: { limits: { per_file_render_timeout: forever } }\n", "decode"},
		{"target no user", strings.Replace(base, "deploy@10.0.0.1", "10.0.0.1", 1), "user@host"},
		{"target with port", strings.Replace(base, "deploy@10.0.0.1", "deploy@10.0.0.1:22", 1), "no port"},
		{"relative known_hosts", strings.Replace(base, "/etc/fpp/known_hosts", "known_hosts", 1), "absolute"},
		{"keep_releases 1", base + "  keep_releases: 1\n", "between 2"},
		{"image host wildcard", strings.Replace(base, "title: t", "title: t\n  allowed_image_hosts: [\"*.example.com\"]", 1), "hostname"},
		{"robots", strings.Replace(base, "title: t", "title: t\n  robots: maybe", 1), "index or noindex"},
		{"language", strings.Replace(base, "title: t", "title: t\n  language: fr", 1), "en or es"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Parse([]byte(tc.doc))
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestDeployOptional(t *testing.T) {
	noDeploy := base[:strings.Index(base, "deploy:")]
	cfg, _ := mustParse(t, noDeploy)
	if cfg.HasDeploy() {
		t.Error("HasDeploy without a deploy section")
	}
	if cfg, _ := mustParse(t, base); !cfg.HasDeploy() {
		t.Error("HasDeploy false with a deploy section")
	}
	// A partial section is still validated in full.
	_, _, err := Parse([]byte(noDeploy + "deploy:\n  target: deploy@10.0.0.1\n"))
	if err == nil || !strings.Contains(err.Error(), "deploy.known_hosts") || !strings.Contains(err.Error(), "deploy.ssh_key") {
		t.Fatalf("partial deploy section: %v", err)
	}
}

func TestWarnings(t *testing.T) {
	doc := strings.Replace(base, "canary_repos: [me/canary-private, me/canary-public]", "canary_repos: [me/canary-private]", 1)
	doc += "gates: { secret_scan: { enabled: false } }\n"
	_, warns := mustParse(t, doc)
	joined := strings.Join(warns, "\n")
	for _, w := range []string{"only one canary", "secret scanning is OFF"} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing warning %q in %q", w, joined)
		}
	}
}

func TestLoadTooLarge(t *testing.T) {
	p := t.TempDir() + "/big.yaml"
	if err := os.WriteFile(p, make([]byte, MaxConfigBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(base))
	f.Add([]byte("publish: { repos: [ { source: a/b, branches: [ {name: x} ] } ] }"))
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, _, err := Parse(data)
		if err != nil {
			return
		}
		// Anything that validates must resolve without panicking and keep
		// the built-in denylist.
		for i := range cfg.Publish.Repos {
			e := cfg.Effective(i)
			if len(e.Exclude) < len(BuiltinExclude) {
				t.Fatal("built-in excludes dropped")
			}
		}
	})
}
