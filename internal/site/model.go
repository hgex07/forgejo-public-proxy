// SPDX-License-Identifier: AGPL-3.0-or-later

package site

import (
	"fpp/internal/config"
	"fpp/internal/render"
)

// Page is what every template receives.
type Page struct {
	Lang      *Lang
	Site      config.Site
	CSS       string
	NoIndex   bool
	Canonical string
	Repo      *RepoView
	Ref       *RefView
	Tab       string
	Crumbs    []Crumb
	Data      any
}

// T translates a message key.
func (p *Page) T(key string, args ...any) string { return p.Lang.T(key, args...) }

// Crumb is one breadcrumb segment; the last has no URL.
type Crumb struct{ Name, URL string }

// Link is a labeled URL.
type Link struct{ Name, URL string }

// RepoView is the repo header and sidebar.
type RepoView struct {
	Slug, Owner, Name string
	HomeURL           string
	Description       string
	Website           string
	Topics            []string
	Archived          bool
	License           string
	Languages         []LangView
	HasCommits        bool
	CommitsURL        string
	BranchesURL       string
	TagsURL           string
	ReleasesURL       string
	ReleasesEnabled   bool
	Archives          bool
	CloneURL          string
	NumBranches       int
	NumTags           int
	NumReleases       int
	Branches, Tags    []*RefView
	LatestRelease     *ReleaseView
}

// LangView is one language in the language bar.
type LangView struct {
	Name, Color, Percent string
	Offset, Width        string // SVG coordinates (viewBox width 100)
}

// RefView is a published branch or tag.
type RefView struct {
	Kind       string
	Public     string
	TreeURL    string
	IsDefault  bool
	Tip        *CommitView
	TagMessage string
	Archives   []Link
}

// CommitView is a commit reference (strip, lists, last change).
type CommitView struct {
	Short, Subject, URL, Author, Date, DateISO string
}

// IndexData is the home page.
type IndexData struct{ Groups []RepoGroup }

// RepoGroup is one namespace on the home page.
type RepoGroup struct {
	Owner string
	Repos []RepoSummary
}

// RepoSummary is one row on the home page.
type RepoSummary struct {
	HomeURL, Name, Description, Updated string
	Archived                            bool
	Language                            *LangView
	Topics                              []string
	sortKey                             string
}

// TreeData is a directory listing.
type TreeData struct {
	Path      string
	ParentURL string
	Entries   []EntryView
	Readme    *ReadmeView
}

// EntryView is one row of a directory listing.
type EntryView struct {
	Name, Kind, URL, Note string
	Last                  *CommitView
}

// ReadmeView is a rendered README.
type ReadmeView struct {
	Name, URL string
	Markdown  render.Safe
	Text      string
}

// BlobData is a file page.
type BlobData struct {
	Path, Name    string
	Size          string
	Lines         int
	Language      string
	RawURL        string
	MediaURL      string
	DownloadURL   string
	RenderedURL   string
	SourceURL     string
	Source        bool
	Bidi          bool
	SymlinkTarget string
	Submodule     string
	LFS           bool
	ImageURL      string
	Binary        bool
	TooLarge      bool
	Markdown      render.Safe
	Code          []render.Safe
}

// CommitsData is a page of a ref's commit list.
type CommitsData struct {
	Days         []DayView
	Newer, Older string
	Truncated    bool
	ShowTime     bool
}

// DayView groups commits by day.
type DayView struct {
	Label, ISO string
	Commits    []CommitView
}

// CommitData is a commit page.
type CommitData struct {
	OID, Short, Subject, Body, Author, Date, DateISO string
	Parents                                          []CommitView
	ChangesKnown                                     bool
	Files                                            []FileChange
	Added, Deleted                                   int
	Hidden                                           int
	Diffs                                            bool
}

// FileChange is one changed file on a commit page.
type FileChange struct {
	Status, Path, Anchor string
	Added, Deleted       int
	Binary               bool
	Note                 string
	Lines                []DiffLineView
}

// DiffLineView is one diff line (Kind is " ", "+", "-" or "@").
type DiffLineView struct {
	Kind, Text, Header string
	Old, New           int
}

// RefsData is the branches or tags page.
type RefsData struct {
	TitleKey string
	Refs     []*RefView
}

// ReleasesData is the releases page (or one release).
type ReleasesData struct{ Releases []*ReleaseView }

// ReleaseView is one release.
type ReleaseView struct {
	Title, Tag, TagURL, URL, Date string
	Prerelease                    bool
	Body                          render.Safe
	Archives                      []Link
}
