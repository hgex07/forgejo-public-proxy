// SPDX-License-Identifier: AGPL-3.0-or-later

package site

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"flag"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/html"

	"fpp/internal/config"
	"fpp/internal/deploy"
	"fpp/internal/forgejo"
	"fpp/internal/policy"
	"fpp/internal/testutil"
)

var update = flag.Bool("update", false, "rewrite golden files")

const siteConfig = `
site: {title: "Code <&>", base_url: "https://code.example.com", theme: a, robots: index, language: LANG}
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
      tags: {include: ["v*"], latest: 2}
      releases: {enabled: true}
      diffs: true
deploy: {target: "deploy@10.0.0.1", ssh_key: {credential: k}, known_hosts: "/etc/fpp/kh"}
`

// pngBytes is a 1×1 PNG.
var pngBytes, _ = base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")

type siteWorld struct {
	out  string
	set  *policy.Set
	cfg  *config.Config
	oids map[string]string
}

func buildSite(t *testing.T, lang string) *siteWorld {
	t.Helper()
	srv := testutil.NewGitServer(t, "bot", "s3cret-token")
	fx := testutil.NewFixture(t)
	o := map[string]string{}

	fx.Write("src/main.go", "package main\n\nfunc main() {\n\tprintln(\"one\")\n}\n")
	fx.Write("README.md", "# old\n")
	o["c1"] = fx.Commit("first")
	fx.Write("src/main.go", "package main\n\nfunc main() {\n\tprintln(\"two\")\n}\n")
	fx.Write("README.md", `# Project

[guide](docs/guide.md) [hidden](secret/x.txt) [env](.env) [abs](/src/main.go#L3)
[internal](https://forgejo.lan/me/proj/src/branch/main/docs/guide.md)
[private](https://forgejo.lan/other/private) [ext](https://example.org/x)

![logo](img/logo.png) ![fake](img/fake.png) ![remote](https://tracker.example/p.gif)

<script>alert(1)</script><a href="javascript:alert(2)">js</a><img src=x onerror=alert(3)>
<div id="clobber" style="color:red" onclick="x()">c</div>
`)
	fx.Write("docs/guide.md", "Back to [readme](../README.md) or [escape](../../../etc/passwd).\n")
	if err := os.MkdirAll(filepath.Join(fx.Dir, "img"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fx.Dir, "img", "logo.png"), pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	fx.Write("img/fake.png", "<html><script>alert(1)</script></html>\n")
	fx.Write("img/evil.svg", `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	fx.Write("bin.txt", "a\x00b")
	fx.Write("pointer.bin", "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 12\n")
	fx.Write("weird <b>&.txt", "x\n")
	fx.Write("index.html/inner.txt", "inner\n")
	fx.Write("subst.txt", "$Format:%ae$\n")
	fx.Write(".gitattributes", "* export-subst\n")
	fx.Write(".env", "TOKEN=planted-secret\n")
	fx.Write("secret/x.txt", "planted-secret\n")
	fx.Write("trojan.go", "package x\n// \u202e evil \u2066\n")
	if err := os.Symlink("/etc/passwd", filepath.Join(fx.Dir, "passwd")); err != nil {
		t.Fatal(err)
	}
	o["c2"] = fx.Commit("second <img src=x onerror=alert(1)>\n\nBody line.")
	fx.Git("tag", "-a", "v1.0", "-m", "release one")
	fx.Publish(srv, "me/proj")
	srv.Allow("me/proj")

	api := &testutil.FakeAPI{
		Srv: srv,
		Repos: map[string]*forgejo.Repo{"me/proj": {
			FullName: "me/proj", DefaultBranch: "main", Description: "demo <b>repo</b>", ObjectFormat: "sha1",
			Website: "javascript:alert(1)", Topics: []string{"go", "<x>"},
		}},
		ReleaseList: map[string][]forgejo.Release{"me/proj": {
			{TagName: "v1.0", Name: "One", Body: "See [readme](README.md). <script>x</script>",
				PublishedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
		}},
	}
	cfg, _, err := config.Parse([]byte(strings.Replace(siteConfig, "LANG", lang, 1)))
	if err != nil {
		t.Fatal(err)
	}
	b := &policy.Builder{Config: cfg, API: api, StateDir: t.TempDir()}
	set, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "site")
	res, err := Generate(context.Background(), Options{Config: cfg, Set: set, Out: out, CloneWork: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(res.Notes, func(n string) bool { return strings.Contains(n, `"index.html"`) }) {
		t.Errorf("no note about the index.html directory: %v", res.Notes)
	}
	return &siteWorld{out: out, set: set, cfg: cfg, oids: o}
}

func (w *siteWorld) read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(w.out, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func (w *siteWorld) exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(w.out, filepath.FromSlash(rel)))
	return err == nil
}

func TestGenerate(t *testing.T) {
	w := buildSite(t, "en")
	base := "pub/proj/"

	// Byte classes: text → raw, real image → media, disguised or binary → dl.
	for rel, want := range map[string]bool{
		base + "raw/main/src/main.go":                   true,
		base + "media/main/img/logo.png":                true,
		base + "media/main/img/evil.svg":                true,
		base + "raw/main/img/fake.png":                  true,
		base + "dl/main/bin.txt":                        true,
		base + "raw/main/pointer.bin":                   true,
		base + "raw/main/weird <b>&.txt":                true,
		base + "media/main/img/fake.png":                false,
		base + "dl/main/img/fake.png":                   false,
		base + "raw/main/bin.txt":                       false,
		base + "raw/main/passwd":                        false,
		base + "raw/main/.env":                          false,
		base + "raw/main/secret/x.txt":                  false,
		base + "blob/main/.env/index.html":              false,
		base + "raw/v1.0/src/main.go":                   true,
		base + "archive/main.zip":                       true,
		base + "archive/v1.0.tar.gz":                    true,
		base + "index.html":                             true,
		base + "tree/main/index.html":                   true,
		base + "tree/main/docs/index.html":              true,
		base + "tree/main/index.html/index.html":        false,
		base + "blob/main/README.md/index.html":         true,
		base + "blob/main/README.md/source/index.html":  true,
		base + "commits/main/index.html":                true,
		base + "commit/" + w.oids["c2"] + "/index.html": true,
		base + "branches/index.html":                    true,
		base + "tags/index.html":                        true,
		base + "releases/index.html":                    true,
		base + "releases/tag/v1.0/index.html":           true,
		"index.html":                                    true, "404.html": true, "robots.txt": true, "sitemap.xml": true,
	} {
		if got := w.exists(rel); got != want {
			t.Errorf("%s exists = %v, want %v", rel, got, want)
		}
	}

	// Identical blobs across refs are hardlinked, not copied.
	a, _ := os.Stat(filepath.Join(w.out, base, "raw/main/src/main.go"))
	b, _ := os.Stat(filepath.Join(w.out, base, "raw/v1.0/src/main.go"))
	if !os.SameFile(a, b) {
		t.Error("identical blob not hardlinked")
	}

	home := w.read(t, base+"index.html")
	for _, want := range []string{
		`<a href="/pub/proj/blob/main/docs/guide.md/">guide</a>`,
		` hidden `, ` env`,
		`<a href="/pub/proj/blob/main/src/main.go/#L3">abs</a>`,
		`<a href="/pub/proj/blob/main/docs/guide.md/">internal</a>`,
		`private <a href="https://example.org/x"`,
		`<a href="https://example.org/x" rel="nofollow noopener noreferrer">ext</a>`,
		`<img src="/pub/proj/media/main/img/logo.png" alt="logo">`,
		`<a href="/pub/proj/blob/main/img/fake.png/">fake</a>`,
		`<a href="https://tracker.example/p.gif" rel="nofollow noopener noreferrer">remote</a>`,
		`id="user-content-clobber"`,
		`demo &lt;b&gt;repo&lt;/b&gt;`,
		`→ /etc/passwd`,
		`/pub/proj/blob/main/weird%20%3Cb%3E&amp;.txt/`,
		`(not browsable)`,
		`<strong>pub</strong>`[0:0] + `<span class="repo-owner">pub</span>`,
		`Code &lt;&amp;&gt;`,
	} {
		if !strings.Contains(home, want) {
			t.Errorf("repo home lacks %q", want)
		}
	}
	if strings.Contains(home, "javascript") || strings.Contains(home, "class=\"website\"") {
		t.Error("javascript: website was rendered")
	}

	guide := w.read(t, base+"blob/main/docs/guide.md/index.html")
	if !strings.Contains(guide, `<a href="/pub/proj/blob/main/README.md/">readme</a>`) || strings.Contains(guide, "passwd</a>") {
		t.Errorf("guide links wrong:\n%s", guide)
	}

	blob := w.read(t, base+"blob/main/src/main.go/index.html")
	for _, want := range []string{`<tr id="L4">`, `<span class="hl-kn">package</span>`, `href="/pub/proj/raw/main/src/main.go"`, "5 lines"} {
		if !strings.Contains(blob, want) {
			t.Errorf("blob page lacks %q", want)
		}
	}
	if !strings.Contains(w.read(t, base+"blob/main/trojan.go/index.html"), `class="banner warn"`) {
		t.Error("no bidi banner")
	}
	if p := w.read(t, base+"blob/main/pointer.bin/index.html"); !strings.Contains(p, "Git LFS") {
		t.Error("LFS pointer not labeled")
	}
	if p := w.read(t, base+"blob/main/img/fake.png/index.html"); strings.Contains(p, "<img") || !strings.Contains(p, "&lt;script&gt;") {
		t.Error("HTML disguised as an image was not shown as escaped text")
	}
	if p := w.read(t, base+"blob/main/bin.txt/index.html"); !strings.Contains(p, "Binary file") || !strings.Contains(p, "/pub/proj/dl/main/bin.txt") {
		t.Error("binary .txt not offered as a download")
	}
	if strings.Contains(home, "forgejo.lan") {
		t.Error("internal Forgejo URL in rendered README")
	}

	commit := w.read(t, base+"commit/"+w.oids["c2"]+"/index.html")
	for _, want := range []string{
		`second &lt;img src=x onerror=alert(1)&gt;`,
		`Body line.`,
		`<a href="/pub/proj/commit/` + w.oids["c1"] + `/">`,
		`class="dc">-	println(&#34;one&#34;)</td>`,
		`class="dc">&#43;	println(&#34;two&#34;)</td>`,
		`@@ -1,5 &#43;1,5 @@`,
		`more changed files are not published`,
	} {
		if !strings.Contains(commit, want) {
			t.Errorf("commit page lacks %q", want)
		}
	}

	rel := w.read(t, base+"releases/tag/v1.0/index.html")
	if !strings.Contains(rel, `<a href="/pub/proj/blob/v1.0/README.md/">readme</a>`) || strings.Contains(rel, "<script>x") {
		t.Errorf("release page:\n%s", rel)
	}
	if rb := w.read(t, "robots.txt"); !strings.Contains(rb, "Disallow: /*/*/raw/") || !strings.Contains(rb, "Sitemap: https://code.example.com/sitemap.xml") {
		t.Errorf("robots.txt:\n%s", rb)
	}

	checkArchives(t, w)
	lintOutput(t, w.out)
}

// checkArchives: archives contain exactly the published files, and
// export-subst is not applied.
func checkArchives(t *testing.T, w *siteWorld) {
	t.Helper()
	var main *policy.Ref
	for _, r := range w.set.Repos[0].Refs {
		if r.Public == "main" {
			main = r
		}
	}
	var want []string
	for _, f := range main.Files {
		if f.Kind != policy.Submodule {
			want = append(want, "proj-main/"+f.Path)
		}
	}
	sort.Strings(want)

	zr, err := zip.OpenReader(filepath.Join(w.out, "pub/proj/archive/main.zip"))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var got []string
	for _, f := range zr.File {
		got = append(got, f.Name)
		if f.Name == "proj-main/subst.txt" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			if string(b) != "$Format:%ae$\n" {
				t.Errorf("export-subst applied: %q", b)
			}
		}
		if f.Name == "proj-main/passwd" && f.Mode()&fs.ModeSymlink == 0 {
			t.Error("symlink stored as a regular file in zip")
		}
	}
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Errorf("zip files\n got %v\nwant %v", got, want)
	}

	f, err := os.Open(filepath.Join(w.out, "pub/proj/archive/main.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	got = nil
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, h.Name)
		if h.Name == "proj-main/passwd" && (h.Typeflag != tar.TypeSymlink || h.Linkname != "/etc/passwd") {
			t.Errorf("tar symlink %+v", h)
		}
	}
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Errorf("tar files\n got %v\nwant %v", got, want)
	}
}

// lintOutput checks invariants every staged site must satisfy. The full
// output lint (internal/lint, which imports this package) has its own
// tests; this one keeps the generator honest on its own.
func lintOutput(t *testing.T, root string) {
	t.Helper()
	// The internal Forgejo URL does appear in raw files and source views
	// here (the fixture README contains it): the gates and the output lint
	// block that before publishing. Rendered pages are checked in
	// TestGenerate.
	planted := []string{"planted-secret", "secret-corp", "s3cret-token", "127.0.0.1:3000"}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() && !fi.IsDir() {
			t.Errorf("%s: not a regular file or directory (%s)", p, fi.Mode())
			return nil
		}
		if d.IsDir() {
			if fi.Mode().Perm() != 0o755 {
				t.Errorf("%s: mode %o", p, fi.Mode().Perm())
			}
			return nil
		}
		if fi.Mode().Perm() != 0o644 {
			t.Errorf("%s: mode %o", p, fi.Mode().Perm())
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, s := range planted {
			if bytes.Contains(data, []byte(s)) {
				t.Errorf("%s contains %q", p, s)
			}
		}
		if strings.HasSuffix(p, ".html") {
			if msg := lintHTML(string(data)); msg != "" {
				t.Errorf("%s: %s", p, msg)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func lintHTML(s string) string {
	z := html.NewTokenizer(strings.NewReader(s))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return ""
		}
		tok := z.Token()
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		switch tok.Data {
		case "script", "iframe", "object", "embed", "form", "base", "style":
			return "forbidden element <" + tok.Data + ">"
		}
		for _, a := range tok.Attr {
			k := strings.ToLower(a.Key)
			if strings.HasPrefix(k, "on") || k == "style" {
				return "forbidden attribute " + k
			}
			v := strings.ToLower(strings.TrimSpace(a.Val))
			if (k == "href" || k == "src") && (strings.HasPrefix(v, "javascript:") || strings.HasPrefix(v, "data:")) {
				return "dangerous URL " + v
			}
		}
	}
}

func TestGolden(t *testing.T) {
	w := buildSite(t, "en")
	pages := map[string]string{
		"home.html":   "pub/proj/index.html",
		"blob.html":   "pub/proj/blob/main/src/main.go/index.html",
		"commit.html": "pub/proj/commit/" + w.oids["c2"] + "/index.html",
		"index.html":  "index.html",
	}
	for golden, rel := range pages {
		got := w.read(t, rel)
		path := filepath.Join("testdata", "golden", golden)
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run go test -update)", err)
		}
		if got != string(want) {
			t.Errorf("%s differs from %s (run go test ./internal/site -update and review the diff)", rel, path)
		}
	}
}

func TestSpanish(t *testing.T) {
	w := buildSite(t, "es")
	home := w.read(t, "pub/proj/index.html")
	for _, want := range []string{`<html lang="es">`, "Código", "Ramas", "Acerca de"} {
		if !strings.Contains(home, want) {
			t.Errorf("es home lacks %q", want)
		}
	}
}

func TestI18nComplete(t *testing.T) {
	verbs := regexp.MustCompile(`%[a-z]`)
	en := Languages["en"]
	for code, l := range Languages {
		for k, v := range en.msgs {
			got, ok := l.msgs[k]
			if !ok {
				t.Errorf("%s: missing %q", code, k)
				continue
			}
			if !slices.Equal(verbs.FindAllString(got, -1), verbs.FindAllString(v, -1)) {
				t.Errorf("%s: %q has different format verbs", code, k)
			}
		}
		if len(l.msgs) != len(en.msgs) {
			t.Errorf("%s has %d messages, en has %d", code, len(l.msgs), len(en.msgs))
		}
	}
	day := time.Date(2026, 9, 3, 15, 4, 0, 0, time.UTC)
	if got := Languages["es"].Day(day); got != "3 sept 2026" {
		t.Errorf("es day %q", got)
	}
	if got := Languages["en"].DateTime(day); got != "Sep 3, 2026 15:04 UTC" {
		t.Errorf("en datetime %q", got)
	}
}

func TestServeContract(t *testing.T) {
	w := buildSite(t, "en")
	h, err := Handler(w.out)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var uris []string
	weak := false // serve the percent-encoded raw variant as HTML, like a broken matcher would
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		uris = append(uris, r.RequestURI)
		bad := weak && strings.Contains(r.RequestURI, "/ra%77/")
		mu.Unlock()
		if bad {
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
			rw.Header().Set("X-Content-Type-Options", "nosniff")
			rw.Write([]byte("<script>alert(1)</script>"))
			return
		}
		h.ServeHTTP(rw, r)
	}))
	defer srv.Close()
	// The same check `fpp check-contract` runs against production Caddy.
	probs, err := CheckContract(context.Background(), srv.URL, "", w.out)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range probs {
		t.Errorf("contract: %s", p)
	}
	// The non-canonical variants reached the server as written.
	for _, want := range []string{"//pub/proj/raw/", "/pub/./proj/raw/", "/pub/proj//raw/", "/pub/proj/ra%77/", "/pub/proj/RAW/", "/pub/proj.gi%74/"} {
		if !slices.ContainsFunc(uris, func(u string) bool { return strings.HasPrefix(u, want) }) {
			t.Errorf("no request starting with %q reached the server", want)
		}
	}
	mu.Lock()
	weak = true
	mu.Unlock()
	probs, err = CheckContract(context.Background(), srv.URL, "", w.out)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(probs, func(p string) bool { return strings.Contains(p, "/ra%77/") && strings.Contains(p, "Content-Type") }) {
		t.Errorf("weak server not reported: %v", probs)
	}
	mu.Lock()
	weak = false
	mu.Unlock()
	if err := os.Symlink("/etc/passwd", filepath.Join(w.out, "leak")); err != nil {
		t.Fatal(err)
	}
	get := func(method, p string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+p, nil)
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	cases := []struct {
		path, status, ctype, csp, disp string
	}{
		{"/", "200", "text/html; charset=utf-8", SiteCSP, ""},
		{"/pub/proj/", "200", "text/html; charset=utf-8", SiteCSP, ""},
		{"/pub/proj", "308", "", "", ""},
		{"/pub/proj/raw/main/src/main.go", "200", "text/plain; charset=utf-8", RawCSP, ""},
		{"/pub/proj/raw/main/weird%20%3Cb%3E&.txt", "200", "text/plain; charset=utf-8", RawCSP, ""},
		{"/pub/proj/media/main/img/logo.png", "200", "image/png", MediaCSP, ""},
		{"/pub/proj/media/main/img/evil.svg", "200", "image/svg+xml", MediaCSP, ""},
		{"/pub/proj/raw/main/img/fake.png", "200", "text/plain; charset=utf-8", RawCSP, ""},
		{"/pub/proj/dl/main/bin.txt", "200", "application/octet-stream", RawCSP, "attachment"},
		{"/pub/proj/archive/main.zip", "200", "application/zip", RawCSP, "attachment"},
		{"/pub/proj/archive/main.tar.gz", "200", "application/gzip", RawCSP, "attachment"},
		{"/pub/proj.git/info/refs?service=git-upload-pack", "200", "application/octet-stream", RawCSP, ""},
		{"/pub/proj.git/HEAD", "200", "application/octet-stream", RawCSP, ""},
		{"/nope/", "404", "text/html; charset=utf-8", SiteCSP, ""},
		{"/leak", "404", "text/html; charset=utf-8", SiteCSP, ""},
		{"/.fpp-site", "404", "text/html; charset=utf-8", SiteCSP, ""},
		{"/pub/proj/raw/main/", "404", "text/html; charset=utf-8", SiteCSP, ""},
		{"/pub/../pub/proj/", "404", "", "", ""},
	}
	for _, c := range cases {
		resp := get("GET", c.path)
		if got := itoa(resp.StatusCode); got != c.status {
			t.Errorf("%s: status %s, want %s", c.path, got, c.status)
			continue
		}
		if c.status == "308" {
			continue
		}
		if c.ctype != "" && resp.Header.Get("Content-Type") != c.ctype {
			t.Errorf("%s: Content-Type %q", c.path, resp.Header.Get("Content-Type"))
		}
		if c.csp != "" && resp.Header.Get("Content-Security-Policy") != c.csp {
			t.Errorf("%s: CSP %q", c.path, resp.Header.Get("Content-Security-Policy"))
		}
		if resp.Header.Get("Content-Disposition") != c.disp {
			t.Errorf("%s: Content-Disposition %q", c.path, resp.Header.Get("Content-Disposition"))
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: no nosniff", c.path)
		}
	}
	if resp := get("POST", "/"); resp.StatusCode != 405 || resp.Header.Get("Allow") != "GET, HEAD" {
		t.Errorf("POST: %d", resp.StatusCode)
	}
	if resp := get("GET", "/_static/"); resp.StatusCode != 404 {
		t.Errorf("directory listing: %d", resp.StatusCode)
	}
	for _, addr := range []string{"0.0.0.0:8080", ":8080", "172.16.0.5:80"} {
		if CheckLoopback(addr) == nil {
			t.Errorf("CheckLoopback(%q) accepted", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:1"} {
		if err := CheckLoopback(addr); err != nil {
			t.Errorf("CheckLoopback(%q): %v", addr, err)
		}
	}
}

func TestResolveRel(t *testing.T) {
	for _, c := range []struct{ dir, p, want string }{
		{"docs", "guide.md", "docs/guide.md"},
		{"docs", "../README.md", "README.md"},
		{"docs", "/src/a.go", "src/a.go"},
		{"", "./x/../y", "y"},
		{"a/b", "..", "a"},
	} {
		if got, ok := resolveRel(c.dir, c.p); !ok || got != c.want {
			t.Errorf("resolveRel(%q,%q) = %q,%v", c.dir, c.p, got, ok)
		}
	}
	for _, p := range []string{"../x", "../../etc/passwd"} {
		if _, ok := resolveRel("", p); ok {
			t.Errorf("resolveRel escaped with %q", p)
		}
	}
}

func TestWriterRejectsCollisionsAndEscapes(t *testing.T) {
	w, err := newWriter(filepath.Join(t.TempDir(), "o"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.write("a/b", []byte("x")); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"a/b", "a", "../x", "/etc/x", "a/../../x", ""} {
		if err := w.write(bad, []byte("y")); err == nil {
			t.Errorf("write(%q) succeeded", bad)
		}
	}
	if err := w.write("big", make([]byte, 2<<20)); err == nil {
		t.Error("size limit not enforced")
	}
}

func TestClone(t *testing.T) {
	w := buildSite(t, "en")
	if home := w.read(t, "pub/proj/index.html"); !strings.Contains(home, "git clone https://code.example.com/pub/proj.git") {
		t.Error("no clone command on the repo home")
	}
	if tag := w.read(t, "pub/proj/tree/v1.0/index.html"); !strings.Contains(tag, "git clone --branch v1.0 https://code.example.com/pub/proj.git") {
		t.Error("no --branch clone command on the tag tree")
	}
	h, err := Handler(w.out)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	home := t.TempDir()
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C", "GIT_TERMINAL_PROMPT=0"}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	dst := filepath.Join(t.TempDir(), "proj")
	git(home, "clone", "-q", srv.URL+"/pub/proj.git", dst)

	var main *policy.Ref
	for _, r := range w.set.Repos[0].Refs {
		if r.Public == "main" {
			main = r
		}
	}
	var want []string
	for _, f := range main.Files {
		if f.Kind != policy.Submodule {
			want = append(want, f.Path)
		}
	}
	sort.Strings(want)
	got := strings.Split(git(dst, "ls-files"), "\n")
	for i, g := range got {
		got[i] = strings.Trim(g, `"`)
	}
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Errorf("cloned files\n got %v\nwant %v", got, want)
	}
	if _, err := os.Stat(filepath.Join(dst, ".env")); err == nil {
		t.Error(".env in clone")
	}
	if target, err := os.Readlink(filepath.Join(dst, "passwd")); err != nil || target != "/etc/passwd" {
		t.Errorf("symlink: %q %v", target, err)
	}
	logs := git(dst, "log", "--all", "--format=%an|%ae|%cn|%ce|%s")
	for _, line := range strings.Split(logs, "\n") {
		f := strings.Split(line, "|")
		if f[1] != "" || f[3] != "" {
			t.Errorf("email in clone commit: %q", line)
		}
		if f[0] != "Alice Example" {
			t.Errorf("author %q", f[0])
		}
	}
	if n := git(dst, "rev-list", "--count", "HEAD"); n != "1" {
		t.Errorf("clone has %s commits on HEAD, want 1", n)
	}
	if b := git(dst, "symbolic-ref", "--short", "HEAD"); b != "main" {
		t.Errorf("HEAD = %s", b)
	}
	if tags := git(dst, "tag"); tags != "v1.0" {
		t.Errorf("tags = %q", tags)
	}
	git(dst, "fsck", "--strict", "--no-progress")
	if strings.Contains(git(dst, "cat-file", "-p", "HEAD"), w.oids["c1"]) {
		t.Error("clone commit references private history")
	}
	git(home, "clone", "-q", "--branch", "v1.0", srv.URL+"/pub/proj.git", filepath.Join(t.TempDir(), "tag"))
}

func TestBuildID(t *testing.T) {
	w := buildSite(t, "en")
	id, err := ReadBuildID(w.out)
	if err != nil || len(id) != 16 {
		t.Fatalf("build.txt %q: %v", id, err)
	}
	gen := func() (string, string) {
		t.Helper()
		out := filepath.Join(t.TempDir(), "site")
		if _, err := Generate(context.Background(), Options{Config: w.cfg, Set: w.set, Out: out, CloneWork: t.TempDir()}); err != nil {
			t.Fatal(err)
		}
		got, err := ReadBuildID(out)
		if err != nil {
			t.Fatal(err)
		}
		return got, out
	}
	// Same publish set → byte-identical site and the same ID (the timer
	// must not create a new release on every run).
	again, out := gen()
	d1, err1 := deploy.Digest(w.out)
	d2, err2 := deploy.Digest(out)
	if again != id || err1 != nil || err2 != nil || d1 != d2 {
		t.Errorf("identical builds differ: id %s/%s digest %s/%s (%v %v)", id, again, d1, d2, err1, err2)
	}
	// Anything that changes what is served changes the ID, including
	// policy and text that leave the file set alone.
	repo := w.set.Repos[0]
	for _, c := range []struct {
		name         string
		change, undo func()
	}{
		{"diffs off", func() { repo.Policy.Diffs = false }, func() { repo.Policy.Diffs = true }},
		{"release body", func() { repo.Releases[0].Body += " edited" }, func() { repo.Releases[0].Body = strings.TrimSuffix(repo.Releases[0].Body, " edited") }},
		{"file removed", func() { repo.Refs[0].Files = repo.Refs[0].Files[1:] }, nil},
	} {
		saved := repo.Refs[0].Files
		c.change()
		if got, _ := gen(); got == id {
			t.Errorf("%s: build ID unchanged", c.name)
		}
		if c.undo != nil {
			c.undo()
		}
		repo.Refs[0].Files = saved
	}
}

func TestLoopbackOnly(t *testing.T) {
	h := LoopbackOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	for host, want := range map[string]int{
		"127.0.0.1:8080":        http.StatusOK,
		"[::1]:8080":            http.StatusOK,
		"localhost:8080":        http.StatusOK,
		"LOCALHOST":             http.StatusOK,
		"attacker.example:8080": http.StatusMisdirectedRequest,
		"127.0.0.1.nip.io":      http.StatusMisdirectedRequest,
		"":                      http.StatusMisdirectedRequest,
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %q: status %d, want %d", host, rec.Code, want)
		}
	}
}
