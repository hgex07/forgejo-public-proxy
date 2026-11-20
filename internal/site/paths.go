// SPDX-License-Identifier: AGPL-3.0-or-later

package site

import (
	"net/url"
	"path"
	"strings"
)

// A route is a list of path segments below the site root. Segments come from
// the publish set (already validated: UTF-8, no control characters, no "."
// or "..", no "/"). URLs percent-encode each segment; file system paths use
// them verbatim.
type route []string

func r(parts ...string) route {
	var out route
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, strings.Split(p, "/")...)
	}
	return out
}

func (rt route) add(parts ...string) route {
	out := append(route(nil), rt...)
	return append(out, r(parts...)...)
}

// URL is the directory-style URL of a page (trailing slash).
func (rt route) URL() string {
	if len(rt) == 0 {
		return "/"
	}
	return rt.FileURL() + "/"
}

// FileURL is the URL of a file (no trailing slash).
func (rt route) FileURL() string {
	var b strings.Builder
	for _, s := range rt {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(s))
	}
	return b.String()
}

// Page is the file system path of the page's index.html.
func (rt route) Page() string { return path.Join(path.Join(rt...), "index.html") }

// File is the file system path of a file.
func (rt route) File() string { return path.Join(rt...) }

// Routes of a repo. slug is "owner/name".
type repoRoutes struct{ base route }

func newRepoRoutes(slug string) repoRoutes { return repoRoutes{base: r(slug)} }

func (p repoRoutes) Home() route                     { return p.base }
func (p repoRoutes) Tree(ref, dir string) route      { return p.base.add("tree", ref, dir) }
func (p repoRoutes) Blob(ref, file string) route     { return p.base.add("blob", ref, file) }
func (p repoRoutes) Source(ref, file string) route   { return p.base.add("blob", ref, file, "source") }
func (p repoRoutes) Bytes(kind, ref, f string) route { return p.base.add(kind, ref, f) }
func (p repoRoutes) Commits(ref string, page int) route {
	if page <= 1 {
		return p.base.add("commits", ref)
	}
	return p.base.add("commits", ref, "page", itoa(page))
}
func (p repoRoutes) Commit(oid string) route   { return p.base.add("commit", oid) }
func (p repoRoutes) Branches() route           { return p.base.add("branches") }
func (p repoRoutes) Tags() route               { return p.base.add("tags") }
func (p repoRoutes) Releases() route           { return p.base.add("releases") }
func (p repoRoutes) Release(tag string) route  { return p.base.add("releases", "tag", tag) }
func (p repoRoutes) Archive(file string) route { return p.base.add("archive", file) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
