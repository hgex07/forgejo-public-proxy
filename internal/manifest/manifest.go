// SPDX-License-Identifier: AGPL-3.0-or-later

// Package manifest records exactly what a publish set exposes (every repo,
// ref, commit and path with its blob ID and size) and diffs two manifests,
// so `fpp plan` can say "these files become public" before anything is.
package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"fpp/internal/policy"
)

// Version is the manifest format version.
const Version = 1

// Manifest is the JSON document. Maps keep the encoding deterministic.
type Manifest struct {
	Version int              `json:"version"`
	Repos   map[string]*Repo `json:"repos"` // by public slug
}

// Repo is one published repository.
type Repo struct {
	Source   string          `json:"source"`
	Refs     map[string]*Ref `json:"refs"` // by public name
	Commits  []string        `json:"commits"`
	Releases []string        `json:"releases,omitempty"`
}

// Ref is one published ref.
type Ref struct {
	Kind   string          `json:"kind"`
	Name   string          `json:"name"`
	Commit string          `json:"commit"`
	Files  map[string]File `json:"files"`
}

// File is one published path.
type File struct {
	Kind string `json:"kind"`
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

// FromSet builds the manifest of a publish set.
func FromSet(s *policy.Set) *Manifest {
	m := &Manifest{Version: Version, Repos: map[string]*Repo{}}
	for _, r := range s.Repos {
		mr := &Repo{Source: r.Source, Refs: map[string]*Ref{}, Commits: []string{}}
		for _, ref := range r.Refs {
			mf := &Ref{Kind: string(ref.Kind), Name: ref.Name, Commit: ref.Commit, Files: map[string]File{}}
			for _, f := range ref.Files {
				mf.Files[f.Path] = File{Kind: string(f.Kind), OID: f.OID, Size: f.Size}
			}
			mr.Refs[ref.Public] = mf
		}
		for oid := range r.Commits {
			mr.Commits = append(mr.Commits, oid)
		}
		sort.Strings(mr.Commits)
		for _, rel := range r.Releases {
			mr.Releases = append(mr.Releases, rel.Tag)
		}
		m.Repos[r.Slug] = mr
	}
	return m
}

const maxBytes = 512 << 20

// Read loads a manifest. A missing file yields (nil, nil): nothing published yet.
func Read(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, maxBytes))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if m.Version != Version {
		return nil, fmt.Errorf("%s: manifest version %d, want %d", path, m.Version, Version)
	}
	return &m, nil
}

// Write stores m atomically (temp file + rename) with mode 0600.
func Write(path string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".manifest-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Diff describes what changes between two manifests. A nil old manifest
// means nothing has been published yet.
type Diff struct {
	Repos []RepoDiff
}

// RepoDiff is the change to one repo.
type RepoDiff struct {
	Slug         string
	New, Removed bool
	RefsAdded    []string
	RefsRemoved  []string
	RefsMoved    []string // tip commit changed
	// Paths are aggregated over all refs of the repo.
	PathsAdded   []string // become public
	PathsChanged []string // content changes
	PathsRemoved []string // no longer published anywhere in the repo
	CommitsAdded int
}

// Empty reports whether nothing changes.
func (d Diff) Empty() bool { return len(d.Repos) == 0 }

// NewRepos lists slugs published for the first time (invariant I8, docs/THREAT_MODEL.md).
func (d Diff) NewRepos() []string {
	var out []string
	for _, r := range d.Repos {
		if r.New {
			out = append(out, r.Slug)
		}
	}
	return out
}

// Compare diffs old (may be nil) against cur.
func Compare(old, cur *Manifest) Diff {
	if old == nil {
		old = &Manifest{Repos: map[string]*Repo{}}
	}
	var d Diff
	for _, slug := range unionKeys(old.Repos, cur.Repos) {
		o, n := old.Repos[slug], cur.Repos[slug]
		rd := RepoDiff{Slug: slug}
		switch {
		case o == nil:
			rd.New = true
			o = &Repo{}
		case n == nil:
			rd.Removed = true
			n = &Repo{}
		case !strings.EqualFold(o.Source, n.Source):
			// A different source repo behind a published slug was never
			// reviewed: it is a first publication too (I8).
			rd.New = true
		}
		for _, name := range unionKeys(o.Refs, n.Refs) {
			or, nr := o.Refs[name], n.Refs[name]
			switch {
			case or == nil:
				rd.RefsAdded = append(rd.RefsAdded, name)
			case nr == nil:
				rd.RefsRemoved = append(rd.RefsRemoved, name)
			case or.Commit != nr.Commit:
				rd.RefsMoved = append(rd.RefsMoved, name)
			}
		}
		op, np := paths(o), paths(n)
		for _, p := range unionKeys(op, np) {
			ov, inOld := op[p]
			nv, inNew := np[p]
			switch {
			case !inOld:
				rd.PathsAdded = append(rd.PathsAdded, p)
			case !inNew:
				rd.PathsRemoved = append(rd.PathsRemoved, p)
			case !sameSet(ov, nv):
				rd.PathsChanged = append(rd.PathsChanged, p)
			}
		}
		oc := map[string]bool{}
		for _, c := range o.Commits {
			oc[c] = true
		}
		for _, c := range n.Commits {
			if !oc[c] {
				rd.CommitsAdded++
			}
		}
		if rd.New || rd.Removed || len(rd.RefsAdded)+len(rd.RefsRemoved)+len(rd.RefsMoved)+
			len(rd.PathsAdded)+len(rd.PathsChanged)+len(rd.PathsRemoved)+rd.CommitsAdded > 0 {
			d.Repos = append(d.Repos, rd)
		}
	}
	return d
}

// paths maps every published path of a repo to the set of blob IDs it has
// across refs.
func paths(r *Repo) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, ref := range r.Refs {
		for p, f := range ref.Files {
			if out[p] == nil {
				out[p] = map[string]bool{}
			}
			out[p][f.OID] = true
		}
	}
	return out
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func unionKeys[V any](a, b map[string]V) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range []map[string]V{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}
