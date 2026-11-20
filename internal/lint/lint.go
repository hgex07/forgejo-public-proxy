// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lint is the output lint: the last check over
// the staged site before anything is pushed. It hard-fails (I7) on:
//
//   - the token, the Forgejo host names or a block leak pattern anywhere:
//     plain files, HTML after entity decoding, archive entries (names and
//     contents) and every object of the clone repos (I2, I5);
//   - symlinks, special files or unexpected permissions;
//   - files the generator did not write, or written files that are missing;
//   - repo bytes (raw/media/dl), archives and clone repos that do not map
//     back to a published repo, ref and path;
//   - HTML with inline or foreign scripts, event-handler or style
//     attributes, dangerous URLs or active elements (I6);
//   - a total size over max_site_bytes.
//
// It knows nothing about how pages were generated; it only reads the
// directory.
package lint

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/net/html"

	"fpp/internal/gates"
	"fpp/internal/gitx"
	"fpp/internal/policy"
	"fpp/internal/site"
)

// Options configure a lint run.
type Options struct {
	Dir     string
	Matcher *gates.Matcher
	// Written is site.Result.Written.
	Written []string
	// Set is what was published.
	Set *policy.Set
	// MaxBytes is max_site_bytes; MaxFileBytes bounds any single file or
	// archive entry read into memory (raw_max_bytes is enough: nothing
	// larger is published).
	MaxBytes, MaxFileBytes int64
	// Work is a private scratch directory (absolute) for auditing clone
	// repos.
	Work string
}

// Problem is one lint failure.
type Problem struct {
	Path string
	Msg  string
}

func (p Problem) String() string { return p.Path + ": " + p.Msg }

// maxProblems stops a run that is clearly broken.
const maxProblems = 200

type linter struct {
	ctx   context.Context
	o     Options
	root  *os.Root
	probs []Problem
	// published is "slug\x00ref\x00path"; refs is "slug\x00ref".
	published map[string]bool
	refs      map[string]bool
	repos     map[string]bool
	clones    map[string]bool
}

// Site lints the staged site in o.Dir. A non-nil error means the lint
// could not run; problems mean it ran and the site must not be published.
func Site(ctx context.Context, o Options) ([]Problem, error) {
	if o.Matcher == nil || o.Set == nil || o.MaxBytes <= 0 || o.MaxFileBytes <= 0 || !filepath.IsAbs(o.Work) {
		return nil, errors.New("lint: incomplete options")
	}
	root, err := os.OpenRoot(o.Dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	l := &linter{ctx: ctx, o: o, root: root, published: map[string]bool{}, refs: map[string]bool{},
		repos: map[string]bool{}, clones: map[string]bool{}}
	for _, r := range o.Set.Repos {
		l.repos[r.Slug] = true
		for _, ref := range r.Refs {
			l.refs[r.Slug+"\x00"+ref.Public] = true
			for _, f := range ref.Files {
				l.published[r.Slug+"\x00"+ref.Public+"\x00"+f.Path] = true
			}
		}
	}

	var files []string
	var total int64
	err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		fi, err := root.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case fi.IsDir():
			if fi.Mode().Perm() != 0o755 || fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
				l.fail(p, "directory mode %s, want 0755", fi.Mode())
			}
		case fi.Mode().IsRegular():
			if fi.Mode().Perm() != 0o644 || fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
				l.fail(p, "file mode %s, want 0644", fi.Mode())
			}
			files = append(files, p)
			total += fi.Size()
		default:
			l.fail(p, "not a regular file or directory (%s)", fi.Mode().Type())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if total > o.MaxBytes {
		l.fail(".", "site is %d bytes, over max_site_bytes %d", total, o.MaxBytes)
	}
	l.checkWritten(files)
	for _, p := range files {
		if len(l.probs) >= maxProblems {
			l.fail(".", "too many problems; stopping")
			break
		}
		if err := l.file(p); err != nil {
			return nil, fmt.Errorf("lint: %s: %w", p, err)
		}
	}
	for dir := range l.clones {
		if err := l.clone(dir); err != nil {
			return nil, fmt.Errorf("lint: %s: %w", dir, err)
		}
	}
	sort.SliceStable(l.probs, func(i, j int) bool { return l.probs[i].Path < l.probs[j].Path })
	return l.probs, nil
}

func (l *linter) fail(p, format string, args ...any) {
	l.probs = append(l.probs, Problem{Path: p, Msg: fmt.Sprintf(format, args...)})
}

// checkWritten compares the files on disk with what the generator wrote.
func (l *linter) checkWritten(files []string) {
	onDisk := map[string]bool{}
	for _, f := range files {
		onDisk[f] = true
	}
	written := map[string]bool{}
	for _, f := range l.o.Written {
		written[f] = true
		if !onDisk[f] {
			l.fail(f, "written by the generator but missing")
		}
	}
	for _, f := range files {
		if !written[f] {
			l.fail(f, "not written by the generator")
		}
	}
}

// topLevel are the only files allowed outside a repo's directory.
var topLevel = map[string]bool{"index.html": true, "404.html": true, "robots.txt": true, "sitemap.xml": true, site.BuildFile: true, site.MarkerFile: true}

// file checks one regular file.
func (l *linter) file(p string) error {
	segs := strings.Split(p, "/")
	class := site.ClassOf("/" + p)
	l.scan(p+" (path)", []byte(p))
	switch {
	case len(segs) == 1:
		if !topLevel[p] {
			l.fail(p, "unexpected top-level file")
		}
	case segs[0] == "_static":
		if len(segs) != 2 {
			l.fail(p, "unexpected static path")
		}
	case len(segs) < 3:
		l.fail(p, "outside any repo directory")
		return nil
	case class == site.PathGit:
		slug := segs[0] + "/" + strings.TrimSuffix(segs[1], ".git")
		if !l.repos[slug] {
			l.fail(p, "clone repo of an unpublished repo %q", slug)
			return nil
		}
		return l.gitFile(p, segs, slug)
	default:
		slug := segs[0] + "/" + segs[1]
		if !l.repos[slug] {
			l.fail(p, "belongs to unpublished repo %q", slug)
			return nil
		}
		switch class {
		case site.PathRaw, site.PathMedia, site.PathDL:
			if len(segs) < 5 || !l.published[slug+"\x00"+segs[3]+"\x00"+strings.Join(segs[4:], "/")] {
				l.fail(p, "repo bytes that map to no published file")
				return nil
			}
		case site.PathArchive:
			name := segs[len(segs)-1]
			ref := strings.TrimSuffix(strings.TrimSuffix(name, ".zip"), ".tar.gz")
			if len(segs) != 4 || ref == name || !l.refs[slug+"\x00"+ref] {
				l.fail(p, "archive that maps to no published ref")
				return nil
			}
			return l.archive(p)
		}
	}
	data, err := l.read(p)
	if err != nil || data == nil {
		return err
	}
	if !l.scan(p, data) && path.Ext(p) == ".html" {
		l.scan(p+" (decoded)", []byte(html.UnescapeString(string(data))))
	}
	if path.Ext(p) == ".html" {
		if msg := checkHTML(data); msg != "" {
			l.fail(p, "%s", msg)
		}
	}
	return nil
}

// read returns a file's contents, or nil (with a problem) when it is over
// the per-file cap.
func (l *linter) read(p string) ([]byte, error) {
	f, err := l.root.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, l.o.MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > l.o.MaxFileBytes {
		l.fail(p, "larger than %d bytes", l.o.MaxFileBytes)
		return nil, nil
	}
	return data, nil
}

func (l *linter) scan(where string, data []byte) bool {
	rule, bad := l.o.Matcher.Blocks(data)
	if bad {
		l.fail(where, "contains a blocked value (%s)", rule)
	}
	return bad
}

// gitFile checks the shape of a clone repo; its objects are audited as a
// whole by clone().
func (l *linter) gitFile(p string, segs []string, slug string) error {
	rel := strings.Join(segs[2:], "/")
	switch {
	case rel == "HEAD" || rel == "info/refs" || rel == "objects/info/packs":
		data, err := l.read(p)
		if err != nil || data == nil {
			return err
		}
		l.scan(p, data)
	case strings.HasPrefix(rel, "objects/pack/pack-") && len(segs) == 5 &&
		(strings.HasSuffix(rel, ".pack") || strings.HasSuffix(rel, ".idx")):
		l.clones[segs[0]+"/"+segs[1]] = true
	default:
		l.fail(p, "unexpected file in the clone repo of %s", slug)
	}
	return nil
}

// clone copies a clone repo's packs into a scratch repo and scans every
// object: compressed packs can't be grepped directly.
func (l *linter) clone(dir string) error {
	scratch, err := os.MkdirTemp(l.o.Work, "lint-clone-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	home := filepath.Join(scratch, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		return err
	}
	g, err := gitx.OpenLocal(filepath.Join(scratch, "r.git"), home)
	if err != nil {
		return err
	}
	if err := g.Init(l.ctx, "sha1"); err != nil {
		return err
	}
	packs, err := fs.Glob(l.root.FS(), path.Join(dir, "objects/pack/pack-*"))
	if err != nil {
		return err
	}
	for _, p := range packs {
		if err := l.copyOut(p, filepath.Join(scratch, "r.git", "objects", "pack", path.Base(p))); err != nil {
			return err
		}
	}
	infos, err := g.AllObjects(l.ctx)
	if err != nil {
		return err
	}
	var batch []string
	var size int64
	flush := func() error {
		objs, err := g.ReadObjects(l.ctx, batch, l.o.MaxFileBytes)
		if err != nil {
			return err
		}
		for _, o := range objs {
			if rule, bad := l.o.Matcher.Blocks(o.Data); bad {
				l.fail(dir, "%s object %.12s contains a blocked value (%s)", o.Type, o.OID, rule)
			}
		}
		batch, size = batch[:0], 0
		return nil
	}
	for _, in := range infos {
		if in.Size > l.o.MaxFileBytes {
			l.fail(dir, "object %.12s is larger than %d bytes", in.OID, l.o.MaxFileBytes)
			continue
		}
		batch = append(batch, in.OID)
		size += in.Size
		if size > policy.MaxBatchBytes {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if len(batch) > 0 {
		return flush()
	}
	return nil
}

func (l *linter) copyOut(p, dst string) error {
	src, err := l.root.Open(p)
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// archive scans every entry name and content of a zip or tar.gz.
func (l *linter) archive(p string) error {
	f, err := l.root.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	entry := func(name string, r io.Reader) error {
		where := p + "!" + name
		l.scan(where, []byte(name))
		data, err := io.ReadAll(io.LimitReader(r, l.o.MaxFileBytes+1))
		if err != nil {
			return err
		}
		if int64(len(data)) > l.o.MaxFileBytes {
			l.fail(where, "entry larger than %d bytes", l.o.MaxFileBytes)
			return nil
		}
		l.scan(where, data)
		return nil
	}
	if strings.HasSuffix(p, ".zip") {
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		zr, err := zip.NewReader(f, fi.Size())
		if err != nil {
			l.fail(p, "unreadable zip: %v", err)
			return nil
		}
		l.scan(p+" (comment)", []byte(zr.Comment))
		for _, ze := range zr.File {
			rc, err := ze.Open()
			if err != nil {
				l.fail(p, "unreadable zip entry: %v", err)
				return nil
			}
			err = entry(ze.Name, rc)
			rc.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		l.fail(p, "unreadable gzip: %v", err)
		return nil
	}
	defer gz.Close()
	l.scan(p+" (gzip header)", []byte(gz.Name+gz.Comment))
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			l.fail(p, "unreadable tar: %v", err)
			return nil
		}
		l.scan(p+"!"+h.Name+" (link)", []byte(h.Linkname+h.Uname+h.Gname))
		for k, v := range h.PAXRecords {
			l.scan(p+"!"+h.Name+" (pax)", []byte(k+"="+v))
		}
		if err := entry(h.Name, tr); err != nil {
			return err
		}
	}
}
