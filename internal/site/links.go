// SPDX-License-Identifier: AGPL-3.0-or-later

package site

import (
	"net/url"
	"regexp"
	"strings"

	"fpp/internal/policy"
	"fpp/internal/render"
)

// linker resolves links in a markdown document at dir inside ref.
// Every target either maps to a published page or file, is
// an external http(s)/mailto URL, or is dropped (rendered as text).
type linker struct {
	g   *gen
	rg  *repoGen
	ref *refGen
	dir string // "" for the repo root
}

var lineFrag = regexp.MustCompile(`^L[0-9]+(-L[0-9]+)?$`)

func (l linker) Href(dest string) (string, bool) {
	u, err := url.Parse(dest)
	if err != nil {
		return "", false
	}
	switch u.Scheme {
	case "mailto":
		return dest, u.Opaque != ""
	case "http", "https":
		if l.g.isForgejoHost(u.Host) {
			return l.g.mapForgejo(u)
		}
		if u.Host == "" {
			return "", false
		}
		return u.String(), true
	case "":
		if u.Host != "" || u.Path == "" {
			return "", false // scheme-relative or query/fragment only
		}
	default:
		return "", false
	}
	p, ok := resolveRel(l.dir, u.Path)
	if !ok {
		return "", false
	}
	target, ok := l.rg.pathURL(l.ref, p)
	if !ok {
		return "", false
	}
	if f := u.Fragment; f != "" {
		if !lineFrag.MatchString(f) && !strings.HasPrefix(f, render.ContentPrefix) {
			f = render.ContentPrefix + f
		}
		target += "#" + url.PathEscape(f)
	}
	return target, true
}

func (l linker) Src(src string) (string, render.ImageMode) {
	u, err := url.Parse(src)
	if err != nil {
		return "", render.ImageDrop
	}
	switch u.Scheme {
	case "http", "https":
		if l.g.isForgejoHost(u.Host) {
			if href, ok := l.g.mapForgejo(u); ok {
				return href, render.ImageLink
			}
			return "", render.ImageDrop
		}
		if u.Host == "" {
			return "", render.ImageDrop
		}
		if l.g.imageHosts[strings.ToLower(u.Hostname())] && u.Scheme == "https" {
			return u.String(), render.ImageShow
		}
		return u.String(), render.ImageLink
	case "":
		if u.Host != "" || u.Path == "" {
			return "", render.ImageDrop
		}
	default:
		return "", render.ImageDrop
	}
	p, ok := resolveRel(l.dir, u.Path)
	if !ok {
		return "", render.ImageDrop
	}
	if f, ok := l.ref.files[p]; ok && f.Kind != policy.Symlink && f.Kind != policy.Submodule {
		if bi := l.rg.blobs[f.OID]; bi != nil && bi.byteClass(p) == classMedia {
			return l.rg.routes.Bytes(classMedia, l.ref.src.Public, p).FileURL(), render.ImageShow
		}
		return l.rg.routes.Blob(l.ref.src.Public, p).URL(), render.ImageLink
	}
	return "", render.ImageDrop
}

// resolveRel resolves a relative URL path against dir; a leading "/" is the
// repo root. It fails for paths escaping the root.
func resolveRel(dir, p string) (string, bool) {
	joined := p
	if !strings.HasPrefix(p, "/") {
		joined = dir + "/" + p
	}
	var out []string
	for _, s := range strings.Split(joined, "/") {
		switch s {
		case "", ".":
		case "..":
			if len(out) == 0 {
				return "", false
			}
			out = out[:len(out)-1]
		default:
			out = append(out, s)
		}
	}
	return strings.Join(out, "/"), true
}

// pathURL maps a path in ref to its published page: a file's blob page or a
// directory's tree page.
func (rg *repoGen) pathURL(ref *refGen, p string) (string, bool) {
	if p == "" {
		return rg.routes.Tree(ref.src.Public, "").URL(), true
	}
	if f, ok := ref.files[p]; ok {
		if f.Kind == policy.Submodule {
			return "", false
		}
		return rg.routes.Blob(ref.src.Public, p).URL(), true
	}
	if _, ok := ref.dirs[p]; ok && browsableDir(p) {
		return rg.routes.Tree(ref.src.Public, p).URL(), true
	}
	return "", false
}

// browsableDir is false for directories whose tree page would collide with
// the parent's index.html.
func browsableDir(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "index.html" {
			return false
		}
	}
	return true
}

func (g *gen) isForgejoHost(host string) bool {
	return host != "" && g.forgejoHosts[strings.ToLower(host)]
}

// mapForgejo maps an absolute URL on the private Forgejo to the public page
// for the same content, if it is published; otherwise the link is dropped
// (internal URLs never reach the output).
func (g *gen) mapForgejo(u *url.URL) (string, bool) {
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) < 2 {
		return "", false
	}
	var rg *repoGen
	for _, cand := range g.repos {
		if strings.EqualFold(cand.src.Source, segs[0]+"/"+strings.TrimSuffix(segs[1], ".git")) {
			rg = cand
		}
	}
	if rg == nil {
		return "", false
	}
	rest := segs[2:]
	if len(rest) == 0 {
		return rg.routes.Home().URL(), true
	}
	switch rest[0] {
	case "src", "raw":
		if len(rest) < 3 || (rest[1] != "branch" && rest[1] != "tag") {
			return "", false
		}
		kind := policy.Branch
		if rest[1] == "tag" {
			kind = policy.Tag
		}
		tail := strings.Join(rest[2:], "/")
		for _, ref := range rg.refs {
			if ref.src.Kind != kind {
				continue
			}
			if tail == ref.src.Name || strings.HasPrefix(tail, ref.src.Name+"/") {
				p := strings.TrimPrefix(strings.TrimPrefix(tail, ref.src.Name), "/")
				return rg.pathURL(ref, p)
			}
		}
	case "commit":
		if len(rest) == 2 {
			if c, ok := rg.src.Commits[rest[1]]; ok && c != nil {
				return rg.routes.Commit(c.OID).URL(), true
			}
		}
	case "releases":
		if rg.src.Policy.Releases {
			return rg.routes.Releases().URL(), true
		}
	}
	return "", false
}
