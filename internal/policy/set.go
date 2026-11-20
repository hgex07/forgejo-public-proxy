// SPDX-License-Identifier: AGPL-3.0-or-later

// Package policy builds the publish set: the single choke point between the
// private Forgejo and everything downstream (invariants I3 and I4).
//
// Later stages (gates, render, lint) never run git or call the API; they
// only see a *Set. Everything in a Set is already filtered by the per-repo
// exposure policy: only allowlisted refs, only commits inside the history
// window, only non-excluded valid paths, no emails, dates at the configured
// precision.
package policy

import (
	"time"

	"fpp/internal/config"
	"fpp/internal/gitx"
)

// Set is everything that will be published.
type Set struct {
	Repos []*Repo
}

// Repo is one published repository.
type Repo struct {
	Source string // Forgejo owner/repo (never rendered)
	Slug   string // public owner/repo
	Policy config.Effective
	Meta   Meta
	// DefaultRef is the public name of the ref shown on the repo home page.
	DefaultRef string
	Refs       []*Ref
	// Commits holds every published commit, keyed by OID.
	Commits  map[string]*Commit
	Releases []Release
	// Skipped lists what the policy dropped, for the exposure report.
	Skipped []Skip

	git *gitx.Repo
	// blobs is every blob OID downstream stages may read: published tree
	// entries and both sides of published changes.
	blobs map[string]bool
}

// Meta is published repository metadata.
type Meta struct {
	Description string
	Website     string
	Topics      []string
	Archived    bool
}

// RefKind distinguishes branches from tags.
type RefKind string

const (
	Branch RefKind = "branch"
	Tag    RefKind = "tag"
)

// Ref is one published branch or tag.
type Ref struct {
	Kind   RefKind
	Name   string // name on Forgejo (never rendered when it differs from Public)
	Public string // URL-safe public name
	Commit string // commit OID (tags are peeled)
	// TagInfo is set for annotated tags.
	TagInfo *TagInfo
	// Window lists the published commits reachable from this ref, newest
	// first. It is never longer than history.max_commits.
	Window []string
	Files  []File
}

// TagInfo is an annotated tag's published metadata.
type TagInfo struct {
	Tagger  string
	Date    time.Time
	Message string
}

// FileKind classifies a tree entry.
type FileKind string

const (
	Regular    FileKind = "file"
	Executable FileKind = "exec"
	Symlink    FileKind = "symlink"
	Submodule  FileKind = "submodule"
)

// File is one published tree entry.
type File struct {
	Path string
	Kind FileKind
	OID  string // blob OID, or the commit OID for submodules
	Size int64  // -1 for submodules
}

// Commit is a published commit.
type Commit struct {
	OID     string
	Parents []Parent
	Author  string    // empty when authors: hidden
	Date    time.Time // UTC, truncated to the day when dates: day
	Message string    // valid UTF-8
	// ChangesKnown is false when the first parent was not fetched (the
	// oldest commits of a shallow window).
	ChangesKnown bool
	Changes      []Change
	// HiddenChanges counts changed paths dropped by excludes or path rules.
	HiddenChanges int
}

// Parent is a parent commit. Only Published parents may be linked (I4).
type Parent struct {
	OID       string
	Published bool
}

// Change is a file changed by a commit, relative to its first parent.
type Change struct {
	Status  string // A, M, D, T
	Path    string
	Added   int // -1 for binary
	Deleted int
	// OldBlob and NewBlob are the blob OIDs on each side ("" when the side
	// is absent or is not a blob, e.g. a submodule). Readable via ReadBlobs.
	OldBlob, NewBlob string
	// OldKind and NewKind classify each side ("" when absent).
	OldKind, NewKind FileKind
}

// Release is a published release.
type Release struct {
	Tag        string // public tag name; always also a published Ref
	Name       string
	Body       string
	Prerelease bool
	Date       time.Time
	Assets     []Asset
}

// Asset is a release attachment (downloaded only when releases.assets).
type Asset struct {
	ID   int64
	Name string
	Size int64
}

// Skip records something the policy did not publish and why.
type Skip struct {
	Ref    string // public ref name, or "" for repo-level items
	Path   string
	Reason string
}
