// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"fpp/internal/config"
	"fpp/internal/forgejo"
	"fpp/internal/gitx"
)

// API is the subset of the Forgejo client the policy needs.
type API interface {
	Repo(ctx context.Context, repo string) (*forgejo.Repo, error)
	Releases(ctx context.Context, repo string) ([]forgejo.Release, error)
	VisibleRepos(ctx context.Context) ([]string, error)
	ProbeHidden(ctx context.Context, repo string) error
	ProbeNoPush(ctx context.Context, repo string) error
	ProbeNoUser(ctx context.Context) (bool, error)
	GitURL(repo string) string
	BasicAuthHeader() string
}

// Builder builds publish sets.
type Builder struct {
	Config *config.Config
	API    API
	// StateDir holds the bare repos (git/) and git's empty HOME (home/).
	StateDir string
}

const maxObjectBytes = 4 << 20 // commits and tags

var publicRefRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

func (b *Builder) home() string { return filepath.Join(b.StateDir, "home") }

func (b *Builder) open(name, remote string) (*gitx.Repo, error) {
	sum := sha256.Sum256([]byte(strings.ToLower(name)))
	dir := filepath.Join(b.StateDir, "git", hex.EncodeToString(sum[:12])+".git")
	return gitx.Open(dir, b.home(), remote, b.API.BasicAuthHeader())
}

// Discovery is the outcome of the access checks.
type Discovery struct {
	Warnings []string
	Visible  []string
}

// Discover runs the per-build access checks. Any error
// means the token can reach something it must not: the build must abort.
func (b *Builder) Discover(ctx context.Context) (*Discovery, error) {
	d := &Discovery{}
	probe, err := b.open("_probe", b.API.GitURL("_probe/_probe"))
	if err != nil {
		return nil, err
	}
	if err := probe.Init(ctx, "sha1"); err != nil {
		return nil, err
	}
	for _, c := range b.Config.Forgejo.CanaryRepos {
		if err := b.API.ProbeHidden(ctx, c); err != nil {
			return nil, err
		}
		if err := probe.ProbeHidden(ctx, b.API.GitURL(c)); err != nil {
			return nil, fmt.Errorf("canary %s: %w", c, err)
		}
	}
	for _, r := range b.Config.Publish.Repos {
		if err := b.API.ProbeNoPush(ctx, r.Source); err != nil {
			return nil, err
		}
	}
	if denied, err := b.API.ProbeNoUser(ctx); err != nil {
		return nil, err
	} else if !denied {
		d.Warnings = append(d.Warnings, "token can read /user: it has scopes beyond read:repository")
	}
	visible, err := b.API.VisibleRepos(ctx)
	if err != nil {
		return nil, err
	}
	d.Visible = visible
	allowed := map[string]bool{}
	for _, r := range b.Config.Publish.Repos {
		allowed[strings.ToLower(r.Source)] = true
	}
	for _, c := range b.Config.Forgejo.CanaryRepos {
		for _, v := range visible {
			if strings.EqualFold(v, c) {
				return nil, fmt.Errorf("canary %s is visible in repos/search", c)
			}
		}
	}
	for _, v := range visible {
		if !allowed[strings.ToLower(v)] {
			d.Warnings = append(d.Warnings, fmt.Sprintf("drift: the bot can see %s, which is not in publish.repos (revoke its access if unintended)", v))
		}
	}
	return d, nil
}

// Build fetches and filters every allowlisted repo. Any per-repo error is
// fatal: v1 publishes all repos or nothing.
func (b *Builder) Build(ctx context.Context) (*Set, error) {
	set := &Set{}
	for i := range b.Config.Publish.Repos {
		r, err := b.buildRepo(ctx, b.Config.Effective(i))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", b.Config.Publish.Repos[i].Source, err)
		}
		set.Repos = append(set.Repos, r)
	}
	return set, nil
}

type wantRef struct {
	kind   RefKind
	name   string
	public string
	local  string
}

func (b *Builder) buildRepo(ctx context.Context, pol config.Effective) (*Repo, error) {
	meta, err := b.API.Repo(ctx, pol.Source)
	if err != nil {
		if forgejo.IsNotFound(err) {
			return nil, errors.New("not readable by the bot (grant it Read, or remove it from publish.repos)")
		}
		return nil, err
	}
	repo := &Repo{
		Source:  pol.Source,
		Slug:    pol.Slug,
		Policy:  pol,
		Meta:    Meta{Description: meta.Description, Website: meta.Website, Topics: meta.Topics, Archived: meta.Archived},
		Commits: map[string]*Commit{},
	}
	if meta.Empty {
		repo.Skipped = append(repo.Skipped, Skip{Reason: "repository is empty"})
		return repo, nil
	}
	g, err := b.open(pol.Source, b.API.GitURL(pol.Source))
	if err != nil {
		return nil, err
	}
	repo.git = g
	if err := g.Init(ctx, meta.ObjectFormat); err != nil {
		return nil, err
	}
	remote, err := g.LsRemote(ctx)
	if err != nil {
		return nil, err
	}
	heads, tags := map[string]bool{}, map[string]bool{}
	for _, r := range remote {
		if n, ok := strings.CutPrefix(r.Name, "refs/heads/"); ok {
			heads[n] = true
		} else if n, ok := strings.CutPrefix(r.Name, "refs/tags/"); ok {
			tags[n] = true
		}
	}

	wants, err := selectRefs(repo, pol, meta.DefaultBranch, heads, tags)
	if err != nil {
		return nil, err
	}
	var releases []forgejo.Release
	if pol.Releases {
		if releases, err = b.API.Releases(ctx, pol.Source); err != nil {
			return nil, err
		}
		wants = addReleaseTags(repo, pol, releases, tags, wants)
	}
	if len(wants) == 0 {
		repo.Skipped = append(repo.Skipped, Skip{Reason: "no configured ref exists"})
		return repo, nil
	}

	depth := 1
	if pol.MaxCommits > 0 {
		depth = pol.MaxCommits + 1 // the parent of the oldest commit, for its file list
	}
	fetch := make([]gitx.FetchRef, len(wants))
	for i, w := range wants {
		prefix := "refs/heads/"
		if w.kind == Tag {
			prefix = "refs/tags/"
		}
		fetch[i] = gitx.FetchRef{Remote: prefix + w.name, Local: w.local}
	}
	if err := g.Fetch(ctx, fetch, depth); err != nil {
		return nil, err
	}
	local, err := g.LocalRefs(ctx)
	if err != nil {
		return nil, err
	}
	byName := map[string]gitx.LocalRef{}
	for _, l := range local {
		byName[l.Name] = l
	}

	limits := b.Config.EffectiveLimits()
	trees := map[string][]gitx.TreeEntry{}
	for _, w := range wants {
		l, ok := byName[w.local]
		if !ok {
			return nil, fmt.Errorf("ref %s missing after fetch", w.name)
		}
		ref := &Ref{Kind: w.kind, Name: w.name, Public: w.public}
		oid, typ := l.OID, l.Type
		for range 5 {
			if typ != "tag" {
				break
			}
			objs, err := g.ReadObjects(ctx, []string{oid}, maxObjectBytes)
			if err != nil {
				return nil, err
			}
			t, err := gitx.ParseTag(objs[0].Data)
			if err != nil {
				return nil, err
			}
			if ref.TagInfo == nil {
				ref.TagInfo = &TagInfo{
					Tagger:  authorName(pol, t.Tagger.Name),
					Date:    dateOf(pol, t.Tagger.When),
					Message: cleanText(t.Message),
				}
			}
			oid, typ = t.Object, t.Type
		}
		if typ != "commit" {
			repo.Skipped = append(repo.Skipped, Skip{Ref: w.public, Reason: "does not point to a commit"})
			continue
		}
		ref.Commit = oid
		if w.kind == Branch {
			if ref.Window, err = g.RevList(ctx, oid, pol.MaxCommits); err != nil {
				return nil, err
			}
		} else if pol.MaxCommits > 0 {
			ref.Window = []string{oid}
		}
		entries, ok := trees[oid]
		if !ok {
			if entries, err = g.LsTree(ctx, oid); err != nil {
				return nil, err
			}
			trees[oid] = entries
		}
		var skips []Skip
		ref.Files, skips = filterTree(entries, pol.Exclude, limits.RawMaxBytes)
		for i := range skips {
			skips[i].Ref = w.public
		}
		repo.Skipped = append(repo.Skipped, skips...)
		if len(ref.Files) > limits.MaxFilesPerRef {
			return nil, fmt.Errorf("ref %s has %d files, over max_files_per_ref %d", w.public, len(ref.Files), limits.MaxFilesPerRef)
		}
		repo.Refs = append(repo.Refs, ref)
	}
	if len(repo.Refs) > 0 {
		repo.DefaultRef = repo.Refs[0].Public
	}
	if err := b.readCommits(ctx, g, repo); err != nil {
		return nil, err
	}
	for _, r := range releases {
		if !releaseIncluded(pol, r) || !hasRef(repo, r.TagName) {
			continue
		}
		rel := Release{Tag: r.TagName, Name: cleanText([]byte(r.Name)), Body: cleanText([]byte(r.Body)),
			Prerelease: r.Prerelease, Date: dateOf(pol, r.PublishedAt)}
		if pol.Assets {
			for _, a := range r.Assets {
				rel.Assets = append(rel.Assets, Asset{ID: a.ID, Name: a.Name, Size: a.Size})
			}
		}
		repo.Releases = append(repo.Releases, rel)
	}
	repo.indexBlobs()
	return repo, nil
}

// changeSide classifies one side of a diff-tree record.
func changeSide(mode, oid string) (FileKind, string) {
	var k FileKind
	switch mode {
	case "100644", "100664":
		k = Regular
	case "100755":
		k = Executable
	case "120000":
		k = Symlink
	case "160000":
		return Submodule, ""
	default:
		return "", ""
	}
	if strings.Trim(oid, "0") == "" {
		return "", ""
	}
	return k, oid
}

func hasRef(r *Repo, public string) bool {
	for _, ref := range r.Refs {
		if ref.Kind == Tag && ref.Public == public {
			return true
		}
	}
	return false
}

func releaseIncluded(pol config.Effective, r forgejo.Release) bool {
	return !r.Draft && (pol.Prereleases || !r.Prerelease)
}

// selectRefs resolves configured branches and tag globs against what the
// remote advertises. Names that cannot be published safely are skipped.
func selectRefs(repo *Repo, pol config.Effective, defaultBranch string, heads, tags map[string]bool) ([]wantRef, error) {
	var wants []wantRef
	publics := map[string]bool{}
	seen := map[string]bool{}
	for _, b := range pol.Branches {
		name, public := b.Name, b.PublicName()
		if name == config.DefaultBranch {
			if defaultBranch == "" {
				return nil, errors.New("repo reports no default branch")
			}
			name = defaultBranch
			if b.As == "" {
				public = defaultBranch
			}
		}
		if !publicRefRe.MatchString(public) || strings.HasSuffix(public, ".lock") {
			return nil, fmt.Errorf("branch %q is not URL-safe; give it an alias: {name: %q, as: <name>}", public, b.Name)
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		if !heads[name] {
			repo.Skipped = append(repo.Skipped, Skip{Ref: public, Reason: "branch does not exist"})
			continue
		}
		if publics[strings.ToLower(public)] {
			return nil, fmt.Errorf("public ref name %q used twice", public)
		}
		publics[strings.ToLower(public)] = true
		wants = append(wants, wantRef{kind: Branch, name: name, public: public, local: gitx.LocalPrefix + "heads/" + name})
	}
	if len(pol.TagInclude) == 0 {
		return wants, nil
	}
	var matched []string
	for t := range tags {
		for _, g := range pol.TagInclude {
			if ok, _ := doublestar.Match(g, t); ok {
				matched = append(matched, t)
				break
			}
		}
	}
	sort.Slice(matched, func(i, j int) bool { return versionLess(matched[j], matched[i]) })
	n := 0
	for _, t := range matched {
		if n >= pol.TagLatest {
			break
		}
		w, ok := tagWant(repo, t, publics)
		if !ok {
			continue
		}
		wants = append(wants, w)
		n++
	}
	return wants, nil
}

func tagWant(repo *Repo, t string, publics map[string]bool) (wantRef, bool) {
	if !publicRefRe.MatchString(t) || strings.HasSuffix(t, ".lock") {
		repo.Skipped = append(repo.Skipped, Skip{Ref: sanitizeName(t), Reason: "tag name is not URL-safe"})
		return wantRef{}, false
	}
	if publics[strings.ToLower(t)] {
		repo.Skipped = append(repo.Skipped, Skip{Ref: t, Reason: "tag name collides with a published branch"})
		return wantRef{}, false
	}
	publics[strings.ToLower(t)] = true
	return wantRef{kind: Tag, name: t, public: t, local: gitx.LocalPrefix + "tags/" + t}, true
}

func addReleaseTags(repo *Repo, pol config.Effective, rels []forgejo.Release, tags map[string]bool, wants []wantRef) []wantRef {
	publics := map[string]bool{}
	have := map[string]bool{}
	for _, w := range wants {
		publics[strings.ToLower(w.public)] = true
		if w.kind == Tag {
			have[w.name] = true
		}
	}
	for _, r := range rels {
		if !releaseIncluded(pol, r) || have[r.TagName] {
			continue
		}
		if !tags[r.TagName] {
			repo.Skipped = append(repo.Skipped, Skip{Ref: sanitizeName(r.TagName), Reason: "release tag does not exist"})
			continue
		}
		if w, ok := tagWant(repo, r.TagName, publics); ok {
			wants = append(wants, w)
			have[r.TagName] = true
		}
	}
	return wants
}

func (b *Builder) readCommits(ctx context.Context, g *gitx.Repo, repo *Repo) error {
	var oids []string
	for _, ref := range repo.Refs {
		for _, o := range ref.Window {
			if _, ok := repo.Commits[o]; !ok {
				repo.Commits[o] = nil
				oids = append(oids, o)
			}
		}
	}
	if len(oids) == 0 {
		return nil
	}
	objs, err := g.ReadObjects(ctx, oids, maxObjectBytes)
	if err != nil {
		return err
	}
	shallow, err := g.Shallow()
	if err != nil {
		return err
	}
	pol := repo.Policy
	for _, o := range objs {
		if o.Type != "commit" {
			return fmt.Errorf("object %s is a %s, not a commit", o.OID, o.Type)
		}
		c, err := gitx.ParseCommit(o.Data)
		if err != nil {
			return fmt.Errorf("commit %s: %w", o.OID, err)
		}
		pc := &Commit{
			OID:     o.OID,
			Author:  authorName(pol, c.Author.Name),
			Date:    dateOf(pol, c.Author.When),
			Message: cleanText(c.Message),
		}
		for _, p := range c.Parents {
			pc.Parents = append(pc.Parents, Parent{OID: p})
		}
		if !shallow[o.OID] {
			parent := ""
			if len(c.Parents) > 0 {
				parent = c.Parents[0]
			}
			changes, err := g.DiffTree(ctx, parent, o.OID)
			if err != nil {
				return err
			}
			pc.ChangesKnown = true
			for _, ch := range changes {
				p := string(ch.Path)
				if pathProblem(p) != "" || excluded(p, pol.Exclude) {
					pc.HiddenChanges++
					continue
				}
				c := Change{Status: string(ch.Status), Path: p, Added: ch.Added, Deleted: ch.Deleted}
				c.OldKind, c.OldBlob = changeSide(ch.OldMode, ch.OldOID)
				c.NewKind, c.NewBlob = changeSide(ch.NewMode, ch.NewOID)
				pc.Changes = append(pc.Changes, c)
			}
		}
		repo.Commits[o.OID] = pc
	}
	for _, c := range repo.Commits {
		for i := range c.Parents {
			_, c.Parents[i].Published = repo.Commits[c.Parents[i].OID]
		}
	}
	return nil
}
