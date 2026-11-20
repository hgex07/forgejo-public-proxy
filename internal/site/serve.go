// SPDX-License-Identifier: AGPL-3.0-or-later

package site

import (
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
)

// The header contract. Production (Caddy) must send exactly
// these; `fpp preview` serves them so problems show up before deploy. The
// header-contract tests check the generated Caddyfile against this table.
const (
	SiteCSP  = "default-src 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	RawCSP   = "default-src 'none'; sandbox"
	MediaCSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"

	PermissionsPolicy = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=(), browsing-topics=()"

	CacheShort     = "public, max-age=300"
	CacheImmutable = "public, max-age=31536000, immutable"
)

// mediaTypes are the Content-Types for allowlisted images, by extension.
var mediaTypes = map[string]string{
	".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
	".webp": "image/webp", ".avif": "image/avif", ".ico": "image/vnd.microsoft.icon", ".svg": "image/svg+xml",
}

// siteTypes are the Content-Types of site-class files by extension (fixed,
// not the system mime table, so preview and the generated Caddyfile agree).
// Anything else is application/octet-stream.
var siteTypes = map[string]string{
	"": "text/html; charset=utf-8", ".html": "text/html; charset=utf-8",
	".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
	".xml": "application/xml; charset=utf-8", ".txt": "text/plain; charset=utf-8",
	".woff": "font/woff", ".woff2": "font/woff2",
}

func init() {
	for ext, t := range mediaTypes {
		siteTypes[ext] = t
	}
}

// PathClass is how a URL path is served.
type PathClass string

const (
	PathSite    PathClass = "site"    // pages and static assets
	PathRaw     PathClass = "raw"     // /{o}/{r}/raw/…
	PathMedia   PathClass = "media"   // /{o}/{r}/media/…
	PathDL      PathClass = "dl"      // /{o}/{r}/dl/…
	PathArchive PathClass = "archive" // /{o}/{r}/archive/…
	PathGit     PathClass = "git"     // /{o}/{r}.git/… (dumb-HTTP clone)
)

// ClassOf classifies a cleaned URL path.
func ClassOf(p string) PathClass {
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(segs) >= 3 && !strings.HasPrefix(segs[0], "_") && strings.HasSuffix(segs[1], ".git") {
		return PathGit
	}
	if len(segs) >= 4 && !strings.HasPrefix(segs[0], "_") {
		switch segs[2] {
		case "raw":
			return PathRaw
		case "media":
			return PathMedia
		case "dl":
			return PathDL
		case "archive":
			return PathArchive
		}
	}
	return PathSite
}

// ContractHeaders sets the response headers for a file at URL path p.
func ContractHeaders(h http.Header, p string) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", PermissionsPolicy)
	h.Set("Cache-Control", CacheShort)
	ext := strings.ToLower(path.Ext(p))
	switch ClassOf(p) {
	case PathRaw:
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Content-Security-Policy", RawCSP)
	case PathMedia:
		if t, ok := mediaTypes[ext]; ok {
			h.Set("Content-Type", t)
		} else {
			h.Set("Content-Type", "application/octet-stream")
		}
		h.Set("Content-Security-Policy", MediaCSP)
	case PathDL:
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Disposition", "attachment")
		h.Set("Content-Security-Policy", RawCSP)
	case PathGit:
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Security-Policy", RawCSP)
	case PathArchive:
		if strings.HasSuffix(p, ".tar.gz") {
			h.Set("Content-Type", "application/gzip")
		} else {
			h.Set("Content-Type", "application/zip")
		}
		h.Set("Content-Disposition", "attachment")
		h.Set("Content-Security-Policy", RawCSP)
	default:
		h.Set("Content-Security-Policy", SiteCSP)
		if t, ok := siteTypes[ext]; ok {
			h.Set("Content-Type", t)
		} else {
			h.Set("Content-Type", "application/octet-stream")
		}
		if strings.HasPrefix(p, "/_static/") {
			h.Set("Cache-Control", CacheImmutable)
		}
	}
}

// Handler serves a staged site with the production header contract: only
// GET/HEAD, no directory listings, no symlinks followed out of the root,
// directory URLs need a trailing slash, custom 404.
func Handler(dir string) (http.Handler, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &handler{root: root}, nil
}

type handler struct{ root *os.Root }

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := req.URL.Path
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "\x00") || path.Clean(p) != strings.TrimSuffix(p, "/") && p != "/" {
		h.notFound(w, req)
		return
	}
	name := strings.Trim(p, "/")
	if name == "" {
		name = "."
	}
	if !fs.ValidPath(name) || strings.HasPrefix(path.Base(name), ".fpp") {
		h.notFound(w, req)
		return
	}
	fi, err := h.root.Lstat(name)
	if err != nil || fi.Mode()&fs.ModeSymlink != 0 {
		h.notFound(w, req)
		return
	}
	if fi.IsDir() {
		if !strings.HasSuffix(p, "/") {
			http.Redirect(w, req, p+"/", http.StatusPermanentRedirect) // as Caddy's file_server
			return
		}
		name = path.Join(name, "index.html")
		p += "index.html"
	} else if strings.HasSuffix(p, "/") {
		h.notFound(w, req)
		return
	}
	h.serveFile(w, req, name, p, http.StatusOK)
}

func (h *handler) serveFile(w http.ResponseWriter, req *http.Request, name, urlPath string, status int) {
	f, err := h.root.Open(name)
	if err != nil {
		if status == http.StatusOK {
			h.notFound(w, req)
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		if status == http.StatusOK {
			h.notFound(w, req)
		}
		return
	}
	ContractHeaders(w.Header(), urlPath)
	if status != http.StatusOK {
		w.Header().Set("Cache-Control", "no-store")
	}
	if status == http.StatusOK {
		http.ServeContent(w, req, "", fi.ModTime(), f)
		return
	}
	w.WriteHeader(status)
	if req.Method != http.MethodHead {
		_, _ = io.Copy(w, f)
	}
}

func (h *handler) notFound(w http.ResponseWriter, req *http.Request) {
	h.serveFile(w, req, "404.html", "/404.html", http.StatusNotFound)
}

// ErrNotLoopback is returned for preview addresses that are not loopback.
var ErrNotLoopback = errors.New("preview: listen address must be loopback (127.0.0.1 or [::1])")

// CheckLoopback validates a preview listen address.
func CheckLoopback(addr string) error {
	host, _, ok := strings.Cut(addr, ":")
	if strings.HasPrefix(addr, "[") {
		host, _, ok = strings.Cut(strings.TrimPrefix(addr, "["), "]")
	}
	if !ok || (host != "127.0.0.1" && host != "::1" && host != "localhost") {
		return ErrNotLoopback
	}
	return nil
}

// LoopbackOnly rejects requests whose Host header is not a loopback name.
// The preview listens on loopback, but a DNS-rebinding page in the
// operator's browser would otherwise reach it under its own host name and
// read staged content (even content the gates blocked, with -ignore-gates).
func LoopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host := req.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		switch strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")) {
		case "127.0.0.1", "::1", "localhost":
			next.ServeHTTP(w, req)
		default:
			http.Error(w, "preview: host must be 127.0.0.1, [::1] or localhost", http.StatusMisdirectedRequest)
		}
	})
}
