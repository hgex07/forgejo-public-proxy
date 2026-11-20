// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clone builds the public clone repository of a published repo: a
// fresh bare repo with one snapshot commit per published branch or tag,
// containing exactly the published files. It is served as static files over
// git's dumb HTTP protocol, so the DMZ runs no git server.
//
// Nothing from the private object store is copied: every object is created
// here from the publish set (policy.Repo.ReadBlobs), so excluded files,
// unpublished history, emails and signatures cannot be in it. Commit IDs
// therefore differ from the private repo.
package clone

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"fpp/internal/gitx"
	"fpp/internal/policy"
)

// epoch is the commit date when the ref's commit date is not published.
var epoch = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

// Build creates the snapshot repo for r under work (recreated from scratch
// on every call) and returns its directory and the files a dumb-HTTP client
// needs, relative to that directory. maxBlob bounds each blob read.
func Build(ctx context.Context, r *policy.Repo, work string, maxBlob int64) (string, []string, error) {
	if !filepath.IsAbs(work) {
		return "", nil, errors.New("clone: work directory must be absolute")
	}
	sum := sha256.Sum256([]byte(strings.ToLower(r.Slug)))
	dir := filepath.Join(work, hex.EncodeToString(sum[:12])+".git")
	home := filepath.Join(work, "home")
	if err := os.RemoveAll(dir); err != nil {
		return "", nil, err
	}
	g, err := gitx.OpenLocal(dir, home)
	if err != nil {
		return "", nil, err
	}
	if err := g.Init(ctx, "sha1"); err != nil {
		return "", nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		bw := bufio.NewWriterSize(pw, 1<<20)
		err := writeStream(ctx, bw, r, maxBlob)
		if err == nil {
			err = bw.Flush()
		}
		pw.CloseWithError(err)
	}()
	if err := g.FastImport(ctx, pr); err != nil {
		pr.CloseWithError(err)
		return "", nil, fmt.Errorf("clone: %w", err)
	}
	head := ""
	for _, ref := range r.Refs {
		if ref.Public == r.DefaultRef && ref.Kind == policy.Branch {
			head = "refs/heads/" + ref.Public
		}
	}
	if err := g.ServeDumb(ctx, head); err != nil {
		return "", nil, fmt.Errorf("clone: %w", err)
	}
	files := []string{"HEAD", "info/refs", "objects/info/packs"}
	packs, err := filepath.Glob(filepath.Join(dir, "objects", "pack", "pack-*"))
	if err != nil {
		return "", nil, err
	}
	for _, p := range packs {
		if strings.HasSuffix(p, ".pack") || strings.HasSuffix(p, ".idx") {
			files = append(files, "objects/pack/"+filepath.Base(p))
		}
	}
	sort.Strings(files)
	return dir, files, nil
}

// writeStream emits a fast-import stream: each published blob once, then
// one parentless commit per ref.
func writeStream(ctx context.Context, w *bufio.Writer, r *policy.Repo, maxBlob int64) error {
	marks := map[string]int{}
	var oids []string
	for _, ref := range r.Refs {
		for _, f := range ref.Files {
			if f.Kind == policy.Submodule {
				continue
			}
			if _, ok := marks[f.OID]; !ok {
				marks[f.OID] = len(marks) + 1
				oids = append(oids, f.OID)
			}
		}
	}
	err := r.ReadBlobs(ctx, oids, maxBlob, func(oid string, data []byte) error {
		fmt.Fprintf(w, "blob\nmark :%d\ndata %d\n", marks[oid], len(data))
		w.Write(data)
		return w.WriteByte('\n')
	})
	if err != nil {
		return err
	}
	for _, ref := range r.Refs {
		prefix := "refs/heads/"
		if ref.Kind == policy.Tag {
			prefix = "refs/tags/"
		}
		name, when, msg := commitMeta(r, ref)
		fmt.Fprintf(w, "commit %s%s\ncommitter %s <> %d +0000\ndata %d\n%s\n",
			prefix, ref.Public, name, when.Unix(), len(msg), msg)
		files := append([]policy.File(nil), ref.Files...)
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		for _, f := range files {
			mode := ""
			switch f.Kind {
			case policy.Regular:
				mode = "100644"
			case policy.Executable:
				mode = "100755"
			case policy.Symlink:
				mode = "120000"
			default:
				continue
			}
			fmt.Fprintf(w, "M %s :%d %s\n", mode, marks[f.OID], quote(f.Path))
		}
		w.WriteByte('\n')
	}
	_, err = w.WriteString("done\n")
	return err
}

// commitMeta describes a ref's snapshot commit using only published data.
func commitMeta(r *policy.Repo, ref *policy.Ref) (string, time.Time, string) {
	name, when := "fpp", epoch
	note := fmt.Sprintf("Published snapshot of %s %s at %.10s.\nOlder history is not published.\n", ref.Kind, ref.Public, ref.Commit)
	msg := note
	if c := r.Commits[ref.Commit]; c != nil {
		if a := cleanName(c.Author); a != "" {
			name = a
		}
		if !c.Date.IsZero() && c.Date.After(epoch) {
			when = c.Date.UTC()
		}
		msg = strings.TrimRight(c.Message, "\n") + "\n\n" + note
	}
	return name, when, msg
}

// cleanName makes an author name valid in a fast-import ident line.
func cleanName(s string) string {
	s = strings.Map(func(c rune) rune {
		if c == '<' || c == '>' || c < 0x20 || c == 0x7f {
			return -1
		}
		return c
	}, s)
	return strings.TrimSpace(s)
}

// quote C-quotes a path for fast-import (always quoted, so leading quotes
// and spaces are unambiguous).
func quote(p string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\n':
			b.WriteString(`\n`)
		default:
			if c < 0x20 || c == 0x7f {
				fmt.Fprintf(&b, "\\%03o", c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
