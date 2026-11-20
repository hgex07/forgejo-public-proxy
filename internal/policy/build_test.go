// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"fpp/internal/config"
	"fpp/internal/forgejo"
	"fpp/internal/testutil"
)

type fakeAPI struct {
	srv      *testutil.GitServer
	repos    map[string]*forgejo.Repo
	releases map[string][]forgejo.Release
	visible  []string
	readable map[string]bool // canaries the API wrongly exposes
	pushable bool
	userOK   bool
}

func (f *fakeAPI) Repo(_ context.Context, repo string) (*forgejo.Repo, error) {
	if r, ok := f.repos[repo]; ok {
		return r, nil
	}
	return nil, &forgejo.StatusError{Path: repo, Code: 404}
}
func (f *fakeAPI) Releases(_ context.Context, repo string) ([]forgejo.Release, error) {
	return f.releases[repo], nil
}
func (f *fakeAPI) VisibleRepos(context.Context) ([]string, error) { return f.visible, nil }
func (f *fakeAPI) ProbeHidden(_ context.Context, repo string) error {
	if f.readable[repo] {
		return fmt.Errorf("canary %s is READABLE through the API", repo)
	}
	return nil
}
func (f *fakeAPI) ProbeNoPush(_ context.Context, repo string) error {
	if f.pushable {
		return errors.New("token can PUSH to " + repo)
	}
	return nil
}
func (f *fakeAPI) ProbeNoUser(context.Context) (bool, error) { return !f.userOK, nil }
func (f *fakeAPI) GitURL(repo string) string                 { return f.srv.RepoURL(repo) }
func (f *fakeAPI) BasicAuthHeader() string {
	return "Basic " + b64(f.srv.User+":"+f.srv.Pass)
}

type world struct {
	srv  *testutil.GitServer
	api  *fakeAPI
	fx   *testutil.Fixture
	oids map[string]string
	cfg  *config.Config
	b    *Builder
}

const testConfig = `
site: {title: t, base_url: "https://code.example.com", theme: a, robots: noindex}
forgejo:
  api_url: "http://127.0.0.1:3000"
  root_url: "https://forgejo.lan"
  user: bot
  token: {credential: tok}
  canary_repos: ["x/canary-private", "x/canary-public"]
publish:
  defaults:
    history: {max_commits: 5}
    exclude: ["secret/**"]
  repos:
    - source: "me/proj"
      slug: "pub/proj"
      branches: ["@default", {name: "feature/x", as: "feature-x"}, "missing"]
      tags: {include: ["v*"], latest: 2}
      releases: {enabled: true}
gates:
  limits: {raw_max_bytes: 1000, render_max_bytes: 500}
deploy: {target: "deploy@10.0.0.1", ssh_key: {credential: k}, known_hosts: "/etc/fpp/kh"}
`

func newWorld(t *testing.T) *world {
	t.Helper()
	srv := testutil.NewGitServer(t, "bot", "s3cret-token")
	fx := testutil.NewFixture(t)
	o := map[string]string{}

	fx.Write("old-secret.txt", "AKIAOLDSECRET\n")
	o["c0"] = fx.Commit("c0: add old secret")
	fx.Git("rm", "-q", "old-secret.txt")
	fx.Write("README.md", "# proj\n")
	o["c1"] = fx.Commit("c1")
	for i := 2; i <= 13; i++ {
		fx.Write("src/a.go", fmt.Sprintf("package a // %d\n", i))
		o[fmt.Sprintf("c%d", i)] = fx.Commit(fmt.Sprintf("c%d", i))
		switch i {
		case 3:
			fx.Git("tag", "v1.0")
		case 5:
			fx.Git("tag", "v1.2")
		case 7:
			fx.Git("tag", "-a", "v1.10", "-m", "release 1.10")
		case 9:
			fx.Git("tag", "v2.0-rc1")
			fx.Git("tag", "other")
			fx.Git("tag", "v3;x")
		case 10:
			fx.Git("checkout", "-q", "-b", "feature/x")
			fx.Write("feature.txt", "f\n")
			o["fx"] = fx.Commit("feature work")
			fx.Git("checkout", "-q", "-b", "dev")
			fx.Write("dev-secret.txt", "dev only\n")
			o["dev"] = fx.Commit("dev only")
			fx.Git("checkout", "-q", "main")
		}
	}
	fx.Write(".env", "TOKEN=x\n")
	fx.Write("keys/id_rsa", "-----BEGIN\n")
	fx.Write("secret/x.txt", "x\n")
	fx.Write("big.bin", strings.Repeat("b", 2000))
	fx.Write("docs/ok.md", "ok\n")
	fx.Write("bad\x01name", "x\n")
	if err := os.Symlink("/etc/passwd", filepath.Join(fx.Dir, "link")); err != nil {
		t.Fatal(err)
	}
	o["files"] = fx.Commit("files")
	fx.Git("update-index", "--add", "--cacheinfo", "160000,"+o["c0"]+",vendor/sub")
	fx.Git("commit", "-q", "-m", "submodule")
	o["sub"] = fx.Git("rev-parse", "HEAD")
	fx.Publish(srv, "me/proj")
	fx.Publish(srv, "x/canary-private")
	srv.Allow("me/proj")

	api := &fakeAPI{
		srv: srv,
		repos: map[string]*forgejo.Repo{"me/proj": {
			FullName: "me/proj", DefaultBranch: "main", Description: "desc", ObjectFormat: "sha1",
		}},
		releases: map[string][]forgejo.Release{"me/proj": {
			{TagName: "v1.0", Name: "One", Body: "notes"},
			{TagName: "v2.0-rc1", Prerelease: true},
			{TagName: "v1.2", Draft: true},
			{TagName: "v9"},
		}},
		visible:  []string{"me/proj"},
		readable: map[string]bool{},
	}
	cfg, _, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	return &world{srv: srv, api: api, fx: fx, oids: o, cfg: cfg,
		b: &Builder{Config: cfg, API: api, StateDir: t.TempDir()}}
}

func b64(s string) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	for i := 0; i < len(s); i += 3 {
		var n uint32
		k := min(3, len(s)-i)
		for j := 0; j < 3; j++ {
			n <<= 8
			if j < k {
				n |= uint32(s[i+j])
			}
		}
		for j := 0; j < 4; j++ {
			if j <= k {
				out = append(out, enc[(n>>(18-6*j))&63])
			} else {
				out = append(out, '=')
			}
		}
	}
	return string(out)
}

func refByPublic(r *Repo, name string) *Ref {
	for _, ref := range r.Refs {
		if ref.Public == name {
			return ref
		}
	}
	return nil
}

func filePaths(ref *Ref) []string {
	var out []string
	for _, f := range ref.Files {
		out = append(out, f.Path)
	}
	return out
}

func TestBuild(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	set, err := w.b.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Repos) != 1 {
		t.Fatalf("repos: %d", len(set.Repos))
	}
	r := set.Repos[0]
	if r.Slug != "pub/proj" || r.DefaultRef != "main" || r.Meta.Description != "desc" {
		t.Errorf("repo: %+v", r)
	}

	var names []string
	for _, ref := range r.Refs {
		names = append(names, string(ref.Kind)+":"+ref.Public)
	}
	want := []string{"branch:main", "branch:feature-x", "tag:v2.0-rc1", "tag:v1.10", "tag:v1.0"}
	if !slices.Equal(names, want) {
		t.Errorf("refs = %v, want %v", names, want)
	}

	main := refByPublic(r, "main")
	if main.Commit != w.oids["sub"] {
		t.Errorf("main tip %s", main.Commit)
	}
	gotFiles := filePaths(main)
	wantFiles := []string{"README.md", "docs/ok.md", "link", "src/a.go", "vendor/sub"}
	if !slices.Equal(gotFiles, wantFiles) {
		t.Errorf("main files = %v, want %v", gotFiles, wantFiles)
	}
	for _, f := range main.Files {
		switch f.Path {
		case "link":
			if f.Kind != Symlink {
				t.Errorf("link kind %s", f.Kind)
			}
		case "vendor/sub":
			if f.Kind != Submodule || f.OID != w.oids["c0"] {
				t.Errorf("submodule %+v", f)
			}
		}
	}
	reasons := map[string]string{}
	for _, s := range r.Skipped {
		reasons[s.Ref+"|"+s.Path] = s.Reason
	}
	for k, v := range map[string]string{
		"main|.env":         "excluded",
		"main|keys/id_rsa":  "excluded",
		"main|secret/x.txt": "excluded",
		"main|big.bin":      "larger than raw_max_bytes",
		"main|bad?name":     "path contains control characters",
		"missing|":          "branch does not exist",
		"v3;x|":             "tag name is not URL-safe",
		"v9|":               "release tag does not exist",
	} {
		if reasons[k] != v {
			t.Errorf("skip %q = %q, want %q", k, reasons[k], v)
		}
	}

	// I4: windows are capped and nothing older is published.
	if len(main.Window) != 5 || main.Window[0] != w.oids["sub"] {
		t.Errorf("main window %v", main.Window)
	}
	fxr := refByPublic(r, "feature-x")
	wantFx := []string{w.oids["fx"], w.oids["c10"], w.oids["c9"], w.oids["c8"], w.oids["c7"]}
	if !slices.Equal(fxr.Window, wantFx) {
		t.Errorf("feature-x window %v", fxr.Window)
	}
	for _, k := range []string{"c0", "c1", "c6", "dev"} {
		if _, ok := r.Commits[w.oids[k]]; ok {
			t.Errorf("commit %s published", k)
		}
	}
	oldest := r.Commits[w.oids["c7"]]
	if !oldest.ChangesKnown || oldest.Parents[0].Published {
		t.Errorf("oldest commit: %+v", oldest)
	}
	if c11 := r.Commits[w.oids["c11"]]; !c11.Parents[0].Published {
		t.Errorf("c11's parent c10 is published via feature-x and should link")
	}
	files := r.Commits[w.oids["files"]]
	var changed []string
	for _, c := range files.Changes {
		changed = append(changed, c.Status+" "+c.Path)
	}
	if !slices.Equal(changed, []string{"A big.bin", "A docs/ok.md", "A link"}) || files.HiddenChanges != 4 {
		t.Errorf("files commit changes %v hidden %d", changed, files.HiddenChanges)
	}

	// Text changes carry real line counts (info/attributes must not force
	// binary) and blob OIDs for diffs.
	for _, c := range files.Changes {
		if c.Path == "docs/ok.md" && (c.Added != 1 || c.Deleted != 0 || c.NewBlob == "" || c.OldBlob != "" || c.NewKind != Regular) {
			t.Errorf("docs/ok.md change %+v", c)
		}
		if c.Path == "link" && c.NewKind != Symlink {
			t.Errorf("link change %+v", c)
		}
	}

	// I3: only published blobs are readable downstream.
	var readme string
	for _, f := range main.Files {
		if f.Path == "README.md" {
			readme = f.OID
		}
	}
	got := map[string]string{}
	if err := r.ReadBlobs(ctx, []string{readme}, 1<<20, func(oid string, data []byte) error {
		got[oid] = string(data)
		return nil
	}); err != nil || got[readme] == "" {
		t.Errorf("ReadBlobs(README) = %v, %q", err, got[readme])
	}
	envOID := w.fx.Git("rev-parse", w.oids["files"]+":.env")
	if err := r.ReadBlobs(ctx, []string{readme, envOID}, 1<<20, func(string, []byte) error { return nil }); err == nil {
		t.Error("ReadBlobs returned an excluded blob")
	}
	if err := r.ReadBlobs(ctx, []string{readme}, 1, func(string, []byte) error { return nil }); err == nil {
		t.Error("ReadBlobs ignored maxSize")
	}

	// Tags: annotated metadata, no history beyond the tagged commit.
	v110 := refByPublic(r, "v1.10")
	if v110.TagInfo == nil || v110.TagInfo.Message != "release 1.10\n" || v110.Commit != w.oids["c7"] {
		t.Errorf("v1.10: %+v %+v", v110, v110.TagInfo)
	}
	if !slices.Equal(v110.Window, []string{w.oids["c7"]}) {
		t.Errorf("tag window %v", v110.Window)
	}

	// Releases: drafts, prereleases and missing tags dropped.
	if len(r.Releases) != 1 || r.Releases[0].Tag != "v1.0" || r.Releases[0].Body != "notes" {
		t.Errorf("releases %+v", r.Releases)
	}

	// Dates are UTC days; no email anywhere (I5).
	c := r.Commits[w.oids["sub"]]
	if c.Author != "Alice Example" || c.Date.Location() != time.UTC || c.Date.Hour() != 0 || c.Date.Minute() != 0 {
		t.Errorf("commit meta %+v", c)
	}
	if dump := fmt.Sprintf("%+v", deref(set)); strings.Contains(dump, "secret-corp") || strings.Contains(dump, "AKIAOLD") {
		t.Errorf("set leaks an email or old content")
	}

	// Unconfigured branches and old history were never fetched.
	assertMissing(t, w.b, "me/proj", w.oids["dev"])
}

func deref(s *Set) string {
	var b strings.Builder
	for _, r := range s.Repos {
		fmt.Fprintf(&b, "%+v\n", *r)
		for _, ref := range r.Refs {
			fmt.Fprintf(&b, "%+v %+v\n", *ref, ref.TagInfo)
		}
		for _, c := range r.Commits {
			fmt.Fprintf(&b, "%+v\n", *c)
		}
	}
	return b.String()
}

func assertMissing(t *testing.T, b *Builder, repo, oid string) {
	t.Helper()
	if _, err := b.open(repo, ""); err == nil {
		t.Fatal("open with empty remote should fail")
	}
	g, err := b.open(repo, "http://unused/")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "cat-file", "-e", oid)
	cmd.Env = []string{"GIT_DIR=" + g.Dir(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "PATH=" + os.Getenv("PATH")}
	if cmd.Run() == nil {
		t.Errorf("object %s was fetched", oid)
	}
}

func TestBuildIsIdempotentAndPrunesRefs(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	if _, err := w.b.Build(ctx); err != nil {
		t.Fatal(err)
	}
	w.cfg.Publish.Repos[0].Branches = []config.RefSpec{{Name: "@default"}}
	w.cfg.Publish.Repos[0].Tags = nil
	w.cfg.Publish.Repos[0].Releases = nil
	set, err := w.b.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(set.Repos[0].Refs); n != 1 {
		t.Fatalf("refs after narrowing: %d", n)
	}
	g, _ := w.b.open("me/proj", w.api.GitURL("me/proj"))
	refs, err := g.LocalRefs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Name != "refs/fpp/heads/main" {
		t.Errorf("stale local refs: %+v", refs)
	}
}

func TestBuildUnreadableRepo(t *testing.T) {
	w := newWorld(t)
	delete(w.api.repos, "me/proj")
	if _, err := w.b.Build(context.Background()); err == nil || !strings.Contains(err.Error(), "not readable") {
		t.Fatalf("got %v", err)
	}
}

func TestBuildDefaultBranchNeedsAlias(t *testing.T) {
	w := newWorld(t)
	w.api.repos["me/proj"].DefaultBranch = "feature/x"
	if _, err := w.b.Build(context.Background()); err == nil || !strings.Contains(err.Error(), "alias") {
		t.Fatalf("got %v", err)
	}
	w.cfg.Publish.Repos[0].Branches = []config.RefSpec{{Name: "@default", As: "fx"}}
	set, err := w.b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := set.Repos[0].Refs[0]; r.Public != "fx" || r.Name != "feature/x" || r.Commit != w.oids["fx"] {
		t.Errorf("%+v", r)
	}
}

func TestDiscover(t *testing.T) {
	ctx := context.Background()
	t.Run("ok with drift warning", func(t *testing.T) {
		w := newWorld(t)
		w.api.visible = []string{"me/proj", "me/other"}
		d, err := w.b.Discover(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Warnings) != 1 || !strings.Contains(d.Warnings[0], "me/other") {
			t.Errorf("warnings %v", d.Warnings)
		}
	})
	for name, mutate := range map[string]func(w *world){
		"canary readable via API":  func(w *world) { w.api.readable["x/canary-public"] = true },
		"canary fetchable via git": func(w *world) { w.srv.Allow("x/canary-private") },
		"canary in search":         func(w *world) { w.api.visible = append(w.api.visible, "X/Canary-Private") },
		"push allowed":             func(w *world) { w.api.pushable = true },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			mutate(w)
			if _, err := w.b.Discover(ctx); err == nil {
				t.Fatal("Discover passed")
			}
		})
	}
	t.Run("git probe inconclusive fails closed", func(t *testing.T) {
		w := newWorld(t)
		w.srv.Close()
		if _, err := w.b.Discover(ctx); err == nil || !strings.Contains(err.Error(), "inconclusive") {
			t.Fatalf("got %v", err)
		}
	})
}
