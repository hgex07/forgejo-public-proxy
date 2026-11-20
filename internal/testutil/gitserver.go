// SPDX-License-Identifier: AGPL-3.0-or-later

// Package testutil serves fixture git repositories over smart HTTP for
// tests, using `git http-backend` behind an auth check that mimics Forgejo:
// repos outside the allowed set answer 404 even when they exist.
package testutil

import (
	"encoding/base64"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// GitServer serves bare repos under Root as http://host/<owner>/<repo>.git.
type GitServer struct {
	*httptest.Server
	Root string
	User string
	Pass string

	mu      sync.Mutex
	allowed map[string]bool
	pushes  int
}

// NewGitServer starts a server; it skips the test if git-http-backend is missing.
func NewGitServer(t *testing.T, user, pass string) *GitServer {
	t.Helper()
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skip("git not available")
	}
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend not available")
	}
	s := &GitServer{Root: t.TempDir(), User: user, Pass: pass, allowed: map[string]bool{}}
	h := &cgi.Handler{
		Path: backend,
		Root: "/",
		Env:  []string{"GIT_PROJECT_ROOT=" + s.Root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.User+":"+s.Pass))
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		repo, _, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), ".git/")
		s.mu.Lock()
		allowed := s.allowed[repo]
		push := strings.HasSuffix(r.URL.Path, "/git-receive-pack") || r.URL.Query().Get("service") == "git-receive-pack"
		if push {
			s.pushes++
		}
		s.mu.Unlock()
		if push && allowed {
			http.Error(w, "read-only", http.StatusForbidden)
			return
		}
		if !ok || !allowed || push {
			http.Error(w, "Not found.", http.StatusNotFound)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// Allow grants the bot read access to repo ("owner/name").
func (s *GitServer) Allow(repo string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowed[repo] = true
}

// PushAttempts counts receive-pack requests (must stay 0 except for probes).
func (s *GitServer) PushAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pushes
}

// URL of repo's git endpoint.
func (s *GitServer) RepoURL(repo string) string { return s.Server.URL + "/" + repo + ".git" }

// Fixture is a non-bare working repo used to author fixture history; it is
// pushed to the server's bare repo with Publish.
type Fixture struct {
	t    *testing.T
	Dir  string
	env  []string
	tick int
}

// NewFixture creates an empty working repo with an isolated git config.
func NewFixture(t *testing.T) *Fixture {
	t.Helper()
	dir := t.TempDir()
	home := t.TempDir()
	f := &Fixture{t: t, Dir: dir, env: []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"LC_ALL=C", "TZ=UTC",
	}}
	f.Git("init", "-q", "-b", "main")
	f.Git("config", "commit.gpgsign", "false")
	f.Git("config", "tag.gpgsign", "false")
	return f
}

// Git runs git in the fixture and returns trimmed stdout.
func (f *Fixture) Git(args ...string) string {
	f.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = f.Dir
	cmd.Env = append(f.env,
		"GIT_AUTHOR_NAME=Alice Example", "GIT_AUTHOR_EMAIL=alice@secret-corp.example",
		"GIT_COMMITTER_NAME=Bob Example", "GIT_COMMITTER_EMAIL=bob@secret-corp.example")
	f.tick++
	date := "@" + itoa(1700000000+f.tick*3600) + " +0530"
	cmd.Env = append(cmd.Env, "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// Write creates or replaces a file (parents created).
func (f *Fixture) Write(path, content string) {
	f.t.Helper()
	p := filepath.Join(f.Dir, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// Commit stages everything and commits; returns the commit OID.
func (f *Fixture) Commit(msg string) string {
	f.t.Helper()
	f.Git("add", "-A")
	f.Git("commit", "-q", "--allow-empty", "-m", msg)
	return f.Git("rev-parse", "HEAD")
}

// Publish mirrors the fixture into the server as repo ("owner/name").
func (f *Fixture) Publish(s *GitServer, repo string) {
	f.t.Helper()
	dst := filepath.Join(s.Root, repo+".git")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if _, err := os.Stat(dst); err != nil {
		f.Git("init", "-q", "--bare", dst)
	}
	f.Git("push", "-q", "--mirror", "--force", dst)
	// Let shallow clients fetch from it.
	cmd := exec.Command("git", "--git-dir", dst, "config", "uploadpack.allowAnySHA1InWant", "true")
	cmd.Env = f.env
	if out, err := cmd.CombinedOutput(); err != nil {
		f.t.Fatalf("%v: %s", err, out)
	}
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if i == len(b) {
		return "0"
	}
	return string(b[i:])
}
