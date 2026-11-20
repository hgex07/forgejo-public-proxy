// SPDX-License-Identifier: AGPL-3.0-or-later

package forgejo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func newTest(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL+"/", "bot", "tok123")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewRejects(t *testing.T) {
	for _, u := range []string{"", "ftp://h", "https://u:p@h", "/rel"} {
		if _, err := New(u, "bot", "t"); err == nil {
			t.Errorf("New(%q) accepted", u)
		}
	}
}

func TestRepoAndAuth(t *testing.T) {
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token tok123" || r.Method != http.MethodGet {
			w.WriteHeader(401)
			return
		}
		switch r.URL.EscapedPath() {
		case "/api/v1/repos/me/proj":
			fmt.Fprint(w, `{"full_name":"me/proj","default_branch":"main","description":"d","topics":["go"],
				"owner":{"email":"owner@corp.example"},"permissions":{"admin":true},"object_format_name":"sha1"}`)
		case "/api/v1/repos/me/renamed":
			fmt.Fprint(w, `{"full_name":"me/other"}`)
		default:
			w.WriteHeader(404)
		}
	})
	ctx := context.Background()
	r, err := c.Repo(ctx, "me/proj")
	if err != nil {
		t.Fatal(err)
	}
	if r.DefaultBranch != "main" || r.Topics[0] != "go" || r.ObjectFormat != "sha1" {
		t.Errorf("%+v", r)
	}
	if dump := fmt.Sprintf("%+v", *r); strings.Contains(dump, "corp.example") {
		t.Error("repo struct carries an email")
	}
	if _, err := c.Repo(ctx, "me/renamed"); err == nil {
		t.Error("renamed repo accepted")
	}
	if _, err := c.Repo(ctx, "me/none"); !IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
}

func TestNoRedirectsAndNoTokenInErrors(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer other.Close()
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	})
	_, err := c.Repo(context.Background(), "me/proj")
	if err == nil || hits.Load() != 0 {
		t.Fatalf("redirect followed: err=%v hits=%d", err, hits.Load())
	}
	if strings.Contains(err.Error(), "tok123") {
		t.Fatal("error leaks the token")
	}
}

func TestResponseCap(t *testing.T) {
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"full_name":"`))
		w.Write([]byte(strings.Repeat("a", MaxResponseBytes+10)))
	})
	if _, err := c.Repo(context.Background(), "me/proj"); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("got %v", err)
	}
}

func TestPagination(t *testing.T) {
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		n := pageSize
		if page == 2 {
			n = 3
		}
		switch r.URL.Path {
		case "/api/v1/repos/search":
			var data []map[string]string
			for i := range n {
				data = append(data, map[string]string{"full_name": fmt.Sprintf("o/r%d-%d", page, i)})
			}
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": data})
		case "/api/v1/repos/me/proj/releases":
			var rels []map[string]any
			for i := range n {
				rels = append(rels, map[string]any{"tag_name": fmt.Sprintf("v%d.%d", page, i), "draft": i == 0,
					"author": map[string]string{"email": "a@corp.example"}})
			}
			json.NewEncoder(w).Encode(rels)
		}
	})
	ctx := context.Background()
	repos, err := c.VisibleRepos(ctx)
	if err != nil || len(repos) != pageSize+3 {
		t.Fatalf("%d %v", len(repos), err)
	}
	rels, err := c.Releases(ctx, "me/proj")
	if err != nil || len(rels) != pageSize+3-2 {
		t.Fatalf("%d %v", len(rels), err)
	}
}

func TestProbes(t *testing.T) {
	status := map[string]int{}
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path
		if r.URL.Query().Get("service") != "" {
			key += "?" + r.URL.Query().Get("service")
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
				w.WriteHeader(500)
				return
			}
		}
		w.WriteHeader(status[key])
	})
	ctx := context.Background()
	for code, ok := range map[int]bool{404: true, 403: true, 401: true, 200: false, 500: false, 302: false} {
		status["/api/v1/repos/x/canary"] = code
		if err := c.ProbeHidden(ctx, "x/canary"); (err == nil) != ok {
			t.Errorf("ProbeHidden %d: %v", code, err)
		}
		status["/me/proj.git/info/refs?git-receive-pack"] = code
		if err := c.ProbeNoPush(ctx, "me/proj"); (err == nil) != (ok && code != 404) {
			t.Errorf("ProbeNoPush %d: %v", code, err)
		}
	}
	status["/api/v1/user"] = 403
	if denied, err := c.ProbeNoUser(ctx); !denied || err != nil {
		t.Error("ProbeNoUser")
	}
	if got := c.GitURL("me/proj"); !strings.HasSuffix(got, "/me/proj.git") {
		t.Error(got)
	}
}
