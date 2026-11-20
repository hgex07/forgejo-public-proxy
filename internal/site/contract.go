// SPDX-License-Identifier: AGPL-3.0-or-later

package site

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// contractHeaders are compared exactly on every 200 response.
var contractHeaders = []string{
	"Content-Type", "Content-Security-Policy", "Content-Disposition", "Cache-Control",
	"X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options",
	"Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Permissions-Policy",
}

// CheckContract requests sample paths of a built site (siteDir) from a
// server at base (sending Host: host when set) and reports every deviation
// from the header contract: one file per path class and extension, plus a
// 404, a hidden file, a directory redirect, a non-GET method and a
// directory listing attempt. It is how the production Caddyfile is
// verified against ContractHeaders.
func CheckContract(ctx context.Context, base, host, siteDir string) ([]string, error) {
	samples, err := contractSamples(siteDir)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var probs []string
	do := func(method, p string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+p, nil)
		if err != nil {
			return nil, err
		}
		if host != "" {
			req.Host = host
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		return resp, nil
	}
	failf := func(p, format string, args ...any) { probs = append(probs, p+": "+fmt.Sprintf(format, args...)) }
	common := func(p string, resp *http.Response) {
		if v := resp.Header.Get("Server"); v != "" {
			failf(p, "Server header %q", v)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			failf(p, "no nosniff")
		}
	}

	for _, s := range samples {
		resp, err := do(http.MethodGet, s.url)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			failf(s.url, "status %d, want 200", resp.StatusCode)
			continue
		}
		want := http.Header{}
		ContractHeaders(want, s.path)
		for _, k := range contractHeaders {
			if got, w := resp.Header.Get(k), want.Get(k); got != w {
				failf(s.url, "%s = %q, want %q", k, got, w)
			}
		}
		common(s.url, resp)
	}

	for _, p := range []string{"/fpp-contract-check-missing/", "/.fpp-site", "/_static/"} {
		resp, err := do(http.MethodGet, p)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusNotFound {
			failf(p, "status %d, want 404", resp.StatusCode)
			continue
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
			failf(p, "404 Content-Type %q", ct)
		}
		if csp := resp.Header.Get("Content-Security-Policy"); csp != SiteCSP {
			failf(p, "404 CSP %q", csp)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			failf(p, "404 Cache-Control %q, want no-store", cc)
		}
		common(p, resp)
	}
	for _, s := range samples {
		if s.dir == "" {
			continue
		}
		resp, err := do(http.MethodGet, s.dir)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusPermanentRedirect || !strings.HasSuffix(resp.Header.Get("Location"), s.dir+"/") {
			failf(s.dir, "status %d Location %q, want 308 to %s/", resp.StatusCode, resp.Header.Get("Location"), s.dir)
		}
		break
	}
	// Non-canonical spellings of repo-byte URLs must never be served with
	// weaker headers (e.g. a raw file as text/html because a matcher saw
	// the undecoded path): each variant is a 404/redirect or gets exactly
	// the canonical file's headers. Sent verbatim, not normalized.
	for _, s := range samples {
		if ClassOf(s.path) == PathSite {
			continue
		}
		want := http.Header{}
		ContractHeaders(want, s.path)
		for _, v := range pathVariants(s.url) {
			resp, err := rawGet(ctx, base, host, v)
			if err != nil {
				return nil, err
			}
			if resp.StatusCode != http.StatusOK {
				continue
			}
			common(v, resp)
			for _, k := range contractHeaders {
				if got, w := resp.Header.Get(k), want.Get(k); got != w {
					failf(v, "%s = %q, want %q (as %s)", k, got, w, s.url)
				}
			}
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, "PROPFIND"} {
		resp, err := do(m, "/")
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET, HEAD" {
			failf("/", "%s: status %d Allow %q, want 405 GET, HEAD", m, resp.StatusCode, resp.Header.Get("Allow"))
		}
	}
	return probs, nil
}

type sample struct {
	path string // decoded URL path (as ContractHeaders sees it)
	url  string // escaped
	dir  string // for directories: the URL without its trailing slash
}

// contractSamples picks one file per (class, extension) from a built site.
func contractSamples(siteDir string) ([]sample, error) {
	seen := map[string]bool{}
	var out []sample
	err := fs.WalkDir(os.DirFS(siteDir), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasPrefix(path.Base(p), ".fpp") {
			return nil
		}
		urlPath := "/" + p
		key := string(ClassOf(urlPath)) + "|" + strings.ToLower(path.Ext(p))
		if path.Base(p) == "index.html" {
			key += "|dir"
		}
		if seen[key] {
			return nil
		}
		seen[key] = true
		s := sample{path: urlPath, url: escapePath(urlPath)}
		if path.Base(p) == "index.html" && p != "index.html" {
			dir := strings.TrimSuffix(urlPath, "index.html")
			s = sample{path: dir + "index.html", url: escapePath(dir), dir: escapePath(strings.TrimSuffix(dir, "/"))}
		}
		out = append(out, s)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].url < out[j].url })
	return out, err
}

func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// pathVariants spells an escaped repo-byte URL path (/owner/repo/<class>/…
// or /owner/repo.git/…) in ways a server or matcher may treat differently:
// a doubled slash, a dot segment, a percent-encoded and an upper-case class
// segment.
func pathVariants(u string) []string {
	segs := strings.Split(strings.TrimPrefix(u, "/"), "/")
	if len(segs) < 3 {
		return nil
	}
	join := func(ss []string) string { return "/" + strings.Join(ss, "/") }
	with := func(i int, v string) string {
		c := append([]string(nil), segs...)
		c[i] = v
		return join(c)
	}
	out := []string{
		"/" + u,
		join(append([]string{segs[0], "."}, segs[1:]...)),
		join(append(append(append([]string(nil), segs[:2]...), ""), segs[2:]...)),
	}
	ci := 2 // the class segment
	if strings.HasSuffix(segs[1], ".git") {
		ci = 1
	}
	seg := segs[ci]
	last := len(seg) - 1
	out = append(out,
		with(ci, seg[:last]+fmt.Sprintf("%%%02X", seg[last])),
		with(ci, strings.ToUpper(seg)))
	return out
}

// rawGet sends GET over a fresh connection with the request target exactly
// as given: Go's client would send some of these spellings differently
// (an Opaque "//…" becomes an absolute URI).
func rawGet(ctx context.Context, base, host, target string) (*http.Response, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("contract: invalid base URL %q", base)
	}
	if strings.ContainsAny(target, " \r\n") || !strings.HasPrefix(target, "/") {
		return nil, fmt.Errorf("contract: invalid request target %q", target)
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), map[string]string{"http": "80", "https": "443"}[u.Scheme])
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var conn net.Conn
	if u.Scheme == "https" {
		conn, err = (&tls.Dialer{Config: &tls.Config{ServerName: u.Hostname()}}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if host == "" {
		host = u.Host
	}
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: fpp-check-contract\r\nConnection: close\r\n\r\n", target, host); err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<20))
	resp.Body.Close()
	return resp, nil
}
