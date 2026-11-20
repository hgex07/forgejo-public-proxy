// SPDX-License-Identifier: AGPL-3.0-or-later

// Package site renders a publish set into a static site.
//
// It reads content only through the publish set (policy.Repo.ReadBlobs),
// writes only through os.Root (writer.go), and produces HTML only through
// html/template plus fragments from internal/render.
package site

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"html/template"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"fpp/internal/clone"
	"fpp/internal/config"
	"fpp/internal/policy"
	"fpp/internal/render"
	"fpp/web"
)

// Options configure a build.
type Options struct {
	Config *config.Config
	Set    *policy.Set
	// Out is the output directory. It must not exist.
	Out string
	// CloneWork is a private directory for building clone snapshots
	// (absolute). Empty disables clone repos.
	CloneWork string
}

// Result summarizes a build.
type Result struct {
	Files int
	Bytes int64
	Pages int
	// Written lists every file written, relative to Out (sorted). The
	// output lint checks that nothing else is there.
	Written []string
	// Notes lists things that were published differently than one might
	// expect (e.g. a directory that cannot be browsed).
	Notes []string
	// BuildID is the content of BuildFile (a hash of everything else written).
	BuildID string
}

// commitsPerPage is the commit list page size.
const commitsPerPage = 50

type gen struct {
	ctx          context.Context
	cfg          *config.Config
	lang         *Lang
	limits       config.Limits
	w            *writer
	tmpl         map[string]*template.Template
	css          string
	md           render.Markdown
	forgejoHosts map[string]bool
	imageHosts   map[string]bool
	repos        []*repoGen
	cloneWork    string
	res          Result
}

type repoGen struct {
	src     *policy.Repo
	routes  repoRoutes
	view    *RepoView
	refs    []*refGen
	blobs   map[string]*blobInfo // by OID
	written map[string]string    // class+OID → first output path (hardlink source)
	dates   bool                 // dates: exact
	langs   map[string]int64     // language bytes of the default ref
	license string
}

type refGen struct {
	src   *policy.Ref
	view  *RefView
	files map[string]*policy.File
	dirs  map[string][]string // dir → child names ("" is the root)
	isDef bool
}

// Generate builds the site into o.Out.
func Generate(ctx context.Context, o Options) (*Result, error) {
	g := &gen{
		ctx:          ctx,
		cfg:          o.Config,
		lang:         LangFor(o.Config.Site.Language),
		limits:       o.Config.EffectiveLimits(),
		forgejoHosts: map[string]bool{},
		imageHosts:   map[string]bool{},
		cloneWork:    o.CloneWork,
	}
	g.md = render.Markdown{HighlightTimeout: g.limits.PerFileRenderTimeout}
	for _, raw := range []string{o.Config.Forgejo.RootURL, o.Config.Forgejo.APIURL} {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			g.forgejoHosts[strings.ToLower(u.Host)] = true
		}
	}
	for _, h := range o.Config.Site.AllowedImageHosts {
		g.imageHosts[strings.ToLower(h)] = true
	}
	var err error
	if g.tmpl, err = loadTemplates(); err != nil {
		return nil, err
	}
	if g.w, err = newWriter(o.Out, g.limits.MaxSiteBytes); err != nil {
		return nil, err
	}
	defer g.w.Close()
	if err := g.static(); err != nil {
		return nil, err
	}
	for _, r := range o.Set.Repos {
		g.repos = append(g.repos, g.prepareRepo(r))
	}
	for _, rg := range g.repos {
		if err := g.genRepo(rg); err != nil {
			return nil, fmt.Errorf("%s: %w", rg.src.Slug, err)
		}
	}
	if err := g.genIndex(); err != nil {
		return nil, err
	}
	if g.res.BuildID, err = g.w.buildID(); err != nil {
		return nil, err
	}
	if err := g.w.write(BuildFile, []byte(g.res.BuildID+"\n")); err != nil {
		return nil, err
	}
	g.res.Files = len(g.w.files)
	for f := range g.w.files {
		g.res.Written = append(g.res.Written, f)
	}
	sort.Strings(g.res.Written)
	g.res.Bytes = g.w.total
	return &g.res, nil
}

func loadTemplates() (map[string]*template.Template, error) {
	funcs := template.FuncMap{"inc": func(i int) int { return i + 1 }}
	base, err := template.New("").Funcs(funcs).ParseFS(web.Templates, "templates/base.html", "templates/partials.html")
	if err != nil {
		return nil, err
	}
	names, err := fs.Glob(web.Templates, "templates/*.html")
	if err != nil {
		return nil, err
	}
	out := map[string]*template.Template{}
	for _, n := range names {
		name := strings.TrimSuffix(path.Base(n), ".html")
		if name == "base" || name == "partials" {
			continue
		}
		t, err := template.Must(base.Clone()).ParseFS(web.Templates, n)
		if err != nil {
			return nil, err
		}
		out[name] = t
	}
	return out, nil
}

func (g *gen) static() error {
	css, err := fs.ReadFile(web.Static, "static/site.css")
	if err != nil {
		return err
	}
	sum := sha256.Sum256(css)
	name := "site." + hex.EncodeToString(sum[:5]) + ".css"
	g.css = r("_static", name).FileURL()
	return g.w.write(r("_static", name).File(), css)
}

func (g *gen) page(tmpl string, rt route, p *Page) error {
	p.Lang, p.Site, p.CSS = g.lang, g.cfg.Site, g.css
	p.NoIndex = g.cfg.Site.Robots == "noindex"
	var buf bytes.Buffer
	if err := g.tmpl[tmpl].ExecuteTemplate(&buf, "base", p); err != nil {
		return fmt.Errorf("template %s: %w", tmpl, err)
	}
	g.res.Pages++
	if rt == nil {
		return g.w.write("404.html", buf.Bytes())
	}
	return g.w.write(rt.Page(), buf.Bytes())
}

func (g *gen) note(format string, args ...any) {
	g.res.Notes = append(g.res.Notes, fmt.Sprintf(format, args...))
}

func (g *gen) date(rg *repoGen, t time.Time) string {
	if t.IsZero() {
		return ""
	}
	if rg.dates {
		return g.lang.DateTime(t)
	}
	return g.lang.Day(t)
}

func dateISO(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func short(oid string) string {
	if len(oid) > 10 {
		return oid[:10]
	}
	return oid
}

func subjectBody(msg string) (string, string) {
	msg = strings.TrimSpace(msg)
	s, b, _ := strings.Cut(msg, "\n")
	return strings.TrimSpace(s), strings.TrimSpace(b)
}

func humanSize(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	case n < 1<<30:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
}

// prepareRepo builds the views that every page of the repo shares (header,
// ref lists) and indexes the trees. Content-dependent parts (languages,
// license) are filled in while the default ref is generated, before any
// page that shows them.
func (g *gen) prepareRepo(src *policy.Repo) *repoGen {
	rg := &repoGen{
		src:     src,
		routes:  newRepoRoutes(src.Slug),
		blobs:   map[string]*blobInfo{},
		written: map[string]string{},
		dates:   src.Policy.Dates == "exact",
		langs:   map[string]int64{},
	}
	owner, name, _ := strings.Cut(src.Slug, "/")
	v := &RepoView{
		Slug: src.Slug, Owner: owner, Name: name,
		HomeURL:         rg.routes.Home().URL(),
		Description:     src.Meta.Description,
		Website:         safeWebsite(src.Meta.Website),
		Topics:          src.Meta.Topics,
		Archived:        src.Meta.Archived,
		BranchesURL:     rg.routes.Branches().URL(),
		TagsURL:         rg.routes.Tags().URL(),
		ReleasesURL:     rg.routes.Releases().URL(),
		ReleasesEnabled: src.Policy.Releases,
		Archives:        src.Policy.Archives,
		NumReleases:     len(src.Releases),
	}
	rg.view = v
	for _, ref := range src.Refs {
		rf := &refGen{src: ref, files: map[string]*policy.File{}, dirs: map[string][]string{"": nil}, isDef: ref.Public == src.DefaultRef}
		for i := range ref.Files {
			f := &ref.Files[i]
			rf.files[f.Path] = f
			addToDirs(rf.dirs, f.Path)
		}
		rf.view = &RefView{
			Kind: string(ref.Kind), Public: ref.Public, IsDefault: rf.isDef,
			TreeURL: rg.routes.Tree(ref.Public, "").URL(),
			Tip:     g.commitView(rg, ref.Commit),
		}
		if ref.TagInfo != nil {
			rf.view.TagMessage, _ = subjectBody(ref.TagInfo.Message)
		}
		if src.Policy.Archives {
			rf.view.Archives = []Link{
				{Name: g.lang.T("source_code_zip"), URL: rg.routes.Archive(ref.Public + ".zip").FileURL()},
				{Name: g.lang.T("source_code_tar"), URL: rg.routes.Archive(ref.Public + ".tar.gz").FileURL()},
			}
		}
		rg.refs = append(rg.refs, rf)
		if ref.Kind == policy.Branch {
			v.Branches = append(v.Branches, rf.view)
		} else {
			v.Tags = append(v.Tags, rf.view)
		}
	}
	v.NumBranches, v.NumTags = len(v.Branches), len(v.Tags)
	if g.cloneWork != "" && src.Policy.Clone && len(src.Refs) > 0 {
		v.CloneURL = strings.TrimSuffix(g.cfg.Site.BaseURL, "/") + "/" + src.Slug + ".git"
	}
	if def := rg.defaultRef(); def != nil && len(def.src.Window) > 0 {
		v.HasCommits = true
		v.CommitsURL = rg.routes.Commits(def.src.Public, 1).URL()
	}
	for i := range src.Releases {
		if !src.Releases[i].Prerelease {
			v.LatestRelease = g.releaseView(rg, &src.Releases[i])
			break
		}
	}
	// The default ref is generated first so the sidebar is complete.
	sort.SliceStable(rg.refs, func(i, j int) bool { return rg.refs[i].isDef && !rg.refs[j].isDef })
	return rg
}

func (rg *repoGen) defaultRef() *refGen {
	for _, rf := range rg.refs {
		if rf.isDef {
			return rf
		}
	}
	return nil
}

func addToDirs(dirs map[string][]string, p string) {
	for {
		dir, name := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		_, seen := dirs[dir]
		dirs[dir] = append(dirs[dir], name)
		if seen || dir == "" {
			return
		}
		p = dir
	}
}

// safeWebsite keeps only absolute http(s) URLs.
func safeWebsite(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return ""
	}
	return u.String()
}

func (g *gen) commitView(rg *repoGen, oid string) *CommitView {
	c := rg.src.Commits[oid]
	if c == nil {
		return &CommitView{Short: short(oid)}
	}
	subj, _ := subjectBody(c.Message)
	return &CommitView{
		Short: short(oid), Subject: subj, URL: rg.routes.Commit(oid).URL(),
		Author: c.Author, Date: g.date(rg, c.Date), DateISO: dateISO(c.Date),
	}
}

func (g *gen) releaseView(rg *repoGen, rel *policy.Release) *ReleaseView {
	title := rel.Name
	if title == "" {
		title = rel.Tag
	}
	v := &ReleaseView{
		Title: title, Tag: rel.Tag, Prerelease: rel.Prerelease,
		URL:    rg.routes.Release(rel.Tag).URL(),
		TagURL: rg.routes.Tree(rel.Tag, "").URL(),
		Date:   g.date(rg, rel.Date),
	}
	if rg.src.Policy.Archives {
		v.Archives = []Link{
			{Name: g.lang.T("source_code_zip"), URL: rg.routes.Archive(rel.Tag + ".zip").FileURL()},
			{Name: g.lang.T("source_code_tar"), URL: rg.routes.Archive(rel.Tag + ".tar.gz").FileURL()},
		}
	}
	return v
}

func (g *gen) basePage(rg *repoGen, rf *refGen, tab string) *Page {
	p := &Page{Repo: rg.view, Tab: tab}
	if rf != nil {
		p.Ref = rf.view
	}
	return p
}

func (g *gen) genRepo(rg *repoGen) error {
	if err := g.classifyBlobs(rg); err != nil {
		return err
	}
	if err := g.genClone(rg); err != nil {
		return err
	}
	for _, rf := range rg.refs {
		if err := g.genRef(rg, rf); err != nil {
			return fmt.Errorf("ref %s: %w", rf.src.Public, err)
		}
	}
	if err := g.genCommits(rg); err != nil {
		return err
	}
	if err := g.genRefLists(rg); err != nil {
		return err
	}
	return g.genReleases(rg)
}

// genClone builds the repo's clone snapshot and copies it to {slug}.git/.
func (g *gen) genClone(rg *repoGen) error {
	if rg.view.CloneURL == "" {
		return nil
	}
	dir, files, err := clone.Build(g.ctx, rg.src, g.cloneWork, g.limits.RawMaxBytes)
	if err != nil {
		return err
	}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f)))
		if err != nil {
			return err
		}
		if err := g.w.write(rg.src.Slug+".git/"+f, data); err != nil {
			return err
		}
	}
	return nil
}

// classifyBlobs reads every published blob once to learn how it is served
// (text, image, download), before any page links to it.
func (g *gen) classifyBlobs(rg *repoGen) error {
	var oids []string
	for _, rf := range rg.refs {
		for _, f := range rf.src.Files {
			if f.Kind == policy.Submodule || f.Kind == policy.Symlink {
				continue
			}
			if _, ok := rg.blobs[f.OID]; !ok {
				rg.blobs[f.OID] = nil
				oids = append(oids, f.OID)
			}
		}
	}
	return rg.src.ReadBlobs(g.ctx, oids, g.limits.RawMaxBytes, func(oid string, data []byte) error {
		rg.blobs[oid] = classify(data)
		return nil
	})
}

// lastChanges maps each path (files and directories) of rf to the newest
// window commit that changed it.
func (g *gen) lastChanges(rg *repoGen, rf *refGen) map[string]*CommitView {
	last := map[string]*CommitView{}
	for _, oid := range rf.src.Window {
		c := rg.src.Commits[oid]
		if c == nil {
			continue
		}
		var cv *CommitView
		for _, ch := range c.Changes {
			for p := ch.Path; ; p = path.Dir(p) {
				if p == "." {
					p = ""
				}
				if _, ok := last[p]; !ok {
					if cv == nil {
						cv = g.commitView(rg, oid)
					}
					last[p] = cv
				}
				if p == "" {
					break
				}
			}
		}
	}
	return last
}

type readme struct {
	rank int
	name string
	data []byte
}

func (g *gen) genRef(rg *repoGen, rf *refGen) error {
	ref := rf.src
	files := append([]policy.File(nil), ref.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	var arch *archiver
	if rg.src.Policy.Archives {
		mtime := time.Time{}
		if c := rg.src.Commits[ref.Commit]; c != nil {
			mtime = c.Date
		}
		_, name, _ := strings.Cut(rg.src.Slug, "/")
		var err error
		arch, err = newArchiver(g.w, rg.routes.Archive(ref.Public+".zip").File(),
			rg.routes.Archive(ref.Public+".tar.gz").File(), name+"-"+ref.Public+"/", mtime)
		if err != nil {
			return err
		}
	}

	readmes := map[string]readme{}
	symlinks := map[string]string{}
	var oids []string
	var order []policy.File
	for _, f := range files {
		if f.Kind == policy.Submodule {
			if err := g.blobPage(rg, rf, f, nil, ""); err != nil {
				return err
			}
			continue
		}
		oids = append(oids, f.OID)
		order = append(order, f)
	}
	i := 0
	err := rg.src.ReadBlobs(g.ctx, oids, g.limits.RawMaxBytes, func(oid string, data []byte) error {
		f := order[i]
		i++
		if arch != nil {
			if err := arch.add(f, data); err != nil {
				return err
			}
		}
		if f.Kind == policy.Symlink {
			target := cleanTarget(data)
			symlinks[f.Path] = target
			return g.blobPage(rg, rf, f, nil, target)
		}
		dir, name := path.Split(f.Path)
		dir = strings.TrimSuffix(dir, "/")
		if rank := readmeRank(name); rank > readmes[dir].rank && int64(len(data)) <= g.limits.RenderMaxBytes {
			readmes[dir] = readme{rank: rank, name: name, data: bytes.Clone(data)}
		}
		if rf.isDef && dir == "" && rg.license == "" && render.IsLicenseFile(name) && rg.blobs[oid].text {
			rg.license = render.DetectLicense(string(data))
		}
		if err := g.writeBytes(rg, rf, f, data); err != nil {
			return err
		}
		lang := ""
		if rg.blobs[oid].text {
			lang = detectLanguage(f.Path, data)
		}
		if rf.isDef && countsForStats(f.Path, lang, data) {
			rg.langs[lang] += int64(len(data))
		}
		return g.blobPage(rg, rf, f, data, lang)
	})
	if err != nil {
		return err
	}
	if arch != nil {
		if err := arch.close(); err != nil {
			return err
		}
	}
	if rf.isDef {
		rg.view.Languages = languageBar(rg.langs)
		rg.view.License = rg.license
	}
	return g.treePages(rg, rf, readmes, symlinks)
}

// cleanTarget makes a symlink target displayable (it is never followed).
func cleanTarget(b []byte) string {
	s := strings.ToValidUTF8(string(b), "�")
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '�'
		}
		return r
	}, s)
}

func (g *gen) writeBytes(rg *repoGen, rf *refGen, f policy.File, data []byte) error {
	class := rg.blobs[f.OID].byteClass(f.Path)
	out := rg.routes.Bytes(class, rf.src.Public, f.Path).File()
	key := class + ":" + f.OID
	if first, ok := rg.written[key]; ok {
		return g.w.link(first, out)
	}
	rg.written[key] = out
	return g.w.write(out, data)
}

func languageBar(langs map[string]int64) []LangView {
	var total int64
	type kv struct {
		name string
		n    int64
	}
	var all []kv
	for k, v := range langs {
		all = append(all, kv{k, v})
		total += v
	}
	if total == 0 {
		return nil
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].name < all[j].name
	})
	if len(all) > 6 {
		var rest int64
		for _, x := range all[5:] {
			rest += x.n
		}
		all = append(all[:5], kv{"Other", rest})
	}
	var out []LangView
	var off float64
	for _, x := range all {
		w := float64(x.n) * 100 / float64(total)
		color := langColor(x.name)
		if x.name == "Other" {
			color = "#8b949e"
		}
		out = append(out, LangView{
			Name: x.name, Color: color, Percent: fmt.Sprintf("%.1f%%", w),
			Offset: fmt.Sprintf("%.3f", off), Width: fmt.Sprintf("%.3f", w),
		})
		off += w
	}
	return out
}

func (g *gen) crumbs(rg *repoGen, rf *refGen, p string) []Crumb {
	_, name, _ := strings.Cut(rg.src.Slug, "/")
	cr := []Crumb{{Name: name, URL: rg.routes.Tree(rf.src.Public, "").URL()}}
	if p == "" {
		cr[0].URL = ""
		return cr
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		c := Crumb{Name: s}
		sub := strings.Join(segs[:i+1], "/")
		if i < len(segs)-1 && browsableDir(sub) {
			c.URL = rg.routes.Tree(rf.src.Public, sub).URL()
		}
		cr = append(cr, c)
	}
	return cr
}

func (g *gen) blobPage(rg *repoGen, rf *refGen, f policy.File, data []byte, langOrTarget string) error {
	ref := rf.src.Public
	_, name := path.Split(f.Path)
	d := &BlobData{Path: f.Path, Name: name}
	p := g.basePage(rg, rf, "code")
	p.Crumbs = g.crumbs(rg, rf, f.Path)
	p.Data = d
	switch f.Kind {
	case policy.Submodule:
		d.Submodule = short(f.OID)
		return g.page("blob", rg.routes.Blob(ref, f.Path), p)
	case policy.Symlink:
		d.SymlinkTarget = langOrTarget
		return g.page("blob", rg.routes.Blob(ref, f.Path), p)
	}
	bi := rg.blobs[f.OID]
	d.Size = humanSize(bi.size)
	d.Language = langOrTarget
	d.Bidi = bi.bidi
	switch bi.byteClass(f.Path) {
	case classMedia:
		d.MediaURL = rg.routes.Bytes(classMedia, ref, f.Path).FileURL()
		d.ImageURL = d.MediaURL
		return g.page("blob", rg.routes.Blob(ref, f.Path), p)
	case classDL:
		d.DownloadURL = rg.routes.Bytes(classDL, ref, f.Path).FileURL()
		d.Binary = true
		return g.page("blob", rg.routes.Blob(ref, f.Path), p)
	}
	d.RawURL = rg.routes.Bytes(classRaw, ref, f.Path).FileURL()
	d.Lines = bi.lines
	if bi.lfs {
		d.LFS = true
		return g.page("blob", rg.routes.Blob(ref, f.Path), p)
	}
	if bi.size > g.limits.RenderMaxBytes {
		d.TooLarge = true
		return g.page("blob", rg.routes.Blob(ref, f.Path), p)
	}
	src := string(data)
	d.Code, _ = render.Highlight(f.Path, "", src, g.limits.PerFileRenderTimeout)
	if !isMarkdown(name) {
		return g.page("blob", rg.routes.Blob(ref, f.Path), p)
	}
	// Markdown: rendered at blob/…/, highlighted source at blob/…/source/.
	d.RenderedURL = rg.routes.Blob(ref, f.Path).URL()
	d.SourceURL = rg.routes.Source(ref, f.Path).URL()
	srcData := *d
	srcData.Source = true
	sp := *p
	sp.Data = &srcData
	if err := g.page("blob", rg.routes.Source(ref, f.Path), &sp); err != nil {
		return err
	}
	dir, _ := path.Split(f.Path)
	d.Markdown = g.md.Render(src, linker{g: g, rg: rg, ref: rf, dir: strings.TrimSuffix(dir, "/")})
	d.Code = nil
	return g.page("blob", rg.routes.Blob(ref, f.Path), p)
}

func (g *gen) treePages(rg *repoGen, rf *refGen, readmes map[string]readme, symlinks map[string]string) error {
	last := g.lastChanges(rg, rf)
	dirs := make([]string, 0, len(rf.dirs))
	for d := range rf.dirs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		if !browsableDir(dir) {
			g.note("%s@%s: directory %q has no tree page (a path segment is named index.html)", rg.src.Slug, rf.src.Public, dir)
			continue
		}
		d := &TreeData{Path: dir}
		if dir != "" {
			parent := path.Dir(dir)
			if parent == "." {
				parent = ""
			}
			d.ParentURL = rg.routes.Tree(rf.src.Public, parent).URL()
		}
		seen := map[string]bool{}
		var subdirs, files []EntryView
		for _, name := range rf.dirs[dir] {
			if seen[name] {
				continue
			}
			seen[name] = true
			full := path.Join(dir, name)
			e := EntryView{Name: name, Last: last[full]}
			if f, ok := rf.files[full]; ok {
				switch f.Kind {
				case policy.Submodule:
					e.Kind = "submodule"
					e.Note = "@ " + short(f.OID)
				case policy.Symlink:
					e.Kind = "symlink"
					e.Note = "→ " + symlinks[full]
				default:
					e.Kind = "file"
				}
				if f.Kind != policy.Submodule {
					e.URL = rg.routes.Blob(rf.src.Public, full).URL()
				}
				files = append(files, e)
				continue
			}
			e.Kind = "dir"
			if browsableDir(full) {
				e.URL = rg.routes.Tree(rf.src.Public, full).URL()
			} else {
				e.Note = g.lang.T("dir_not_published")
			}
			subdirs = append(subdirs, e)
		}
		byName := func(es []EntryView) {
			sort.Slice(es, func(i, j int) bool {
				a, b := strings.ToLower(es[i].Name), strings.ToLower(es[j].Name)
				if a != b {
					return a < b
				}
				return es[i].Name < es[j].Name
			})
		}
		byName(subdirs)
		byName(files)
		d.Entries = append(subdirs, files...)
		if rm, ok := readmes[dir]; ok {
			full := path.Join(dir, rm.name)
			v := &ReadmeView{Name: rm.name, URL: rg.routes.Blob(rf.src.Public, full).URL()}
			if isMarkdown(rm.name) {
				v.Markdown = g.md.Render(string(rm.data), linker{g: g, rg: rg, ref: rf, dir: dir})
			} else if render.IsText(rm.data) {
				v.Text = string(rm.data)
			}
			if !v.Markdown.IsZero() || v.Text != "" {
				d.Readme = v
			}
		}
		p := g.basePage(rg, rf, "code")
		p.Crumbs = g.crumbs(rg, rf, dir)
		p.Data = d
		if err := g.page("tree", rg.routes.Tree(rf.src.Public, dir), p); err != nil {
			return err
		}
		if dir == "" && rf.isDef {
			hp := *p
			hp.Canonical = g.canonical(rg.routes.Home())
			if err := g.page("tree", rg.routes.Home(), &hp); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *gen) canonical(rt route) string {
	base := strings.TrimSuffix(g.cfg.Site.BaseURL, "/")
	if base == "" {
		return ""
	}
	return base + rt.URL()
}

func (g *gen) genCommits(rg *repoGen) error {
	// Per-ref commit lists.
	for _, rf := range rg.refs {
		win := rf.src.Window
		if rf.src.Kind != policy.Branch || len(win) == 0 {
			continue
		}
		pages := (len(win) + commitsPerPage - 1) / commitsPerPage
		oldest := rg.src.Commits[win[len(win)-1]]
		truncated := oldest != nil && len(oldest.Parents) > 0
		for pg := 1; pg <= pages; pg++ {
			d := &CommitsData{ShowTime: rg.dates}
			chunk := win[(pg-1)*commitsPerPage : min(pg*commitsPerPage, len(win))]
			for _, oid := range chunk {
				c := rg.src.Commits[oid]
				if c == nil {
					continue
				}
				label := g.lang.Day(c.Date)
				if len(d.Days) == 0 || d.Days[len(d.Days)-1].Label != label {
					d.Days = append(d.Days, DayView{Label: label, ISO: c.Date.UTC().Format("2006-01-02")})
				}
				day := &d.Days[len(d.Days)-1]
				day.Commits = append(day.Commits, *g.commitView(rg, oid))
			}
			if pg > 1 {
				d.Newer = rg.routes.Commits(rf.src.Public, pg-1).URL()
			}
			if pg < pages {
				d.Older = rg.routes.Commits(rf.src.Public, pg+1).URL()
			} else {
				d.Truncated = truncated
			}
			p := g.basePage(rg, rf, "commits")
			p.Data = d
			if err := g.page("commits", rg.routes.Commits(rf.src.Public, pg), p); err != nil {
				return err
			}
		}
	}
	// One page per published commit.
	oids := make([]string, 0, len(rg.src.Commits))
	for oid := range rg.src.Commits {
		oids = append(oids, oid)
	}
	sort.Strings(oids)
	def := rg.defaultRef()
	for _, oid := range oids {
		if err := g.commitPage(rg, def, rg.src.Commits[oid]); err != nil {
			return err
		}
	}
	return nil
}

func (g *gen) commitPage(rg *repoGen, def *refGen, c *policy.Commit) error {
	if c == nil {
		return nil
	}
	subj, body := subjectBody(c.Message)
	d := &CommitData{
		OID: c.OID, Short: short(c.OID), Subject: subj, Body: body, Author: c.Author,
		Date: g.date(rg, c.Date), DateISO: dateISO(c.Date),
		ChangesKnown: c.ChangesKnown, Hidden: c.HiddenChanges,
		Diffs: rg.src.Policy.Diffs,
	}
	for _, par := range c.Parents {
		pv := CommitView{Short: short(par.OID)}
		if par.Published {
			pv.URL = rg.routes.Commit(par.OID).URL()
		}
		d.Parents = append(d.Parents, pv)
	}
	contents := map[string]string{}
	if d.Diffs && c.ChangesKnown {
		var want []string
		for _, ch := range c.Changes {
			for _, o := range []string{ch.OldBlob, ch.NewBlob} {
				if o != "" {
					want = append(want, o)
				}
			}
		}
		sizes, err := rg.src.BlobSizes(g.ctx, want)
		if err != nil {
			return err
		}
		var small []string
		for _, o := range want {
			if sizes[o] <= g.limits.RenderMaxBytes {
				small = append(small, o)
			}
		}
		if err := rg.src.ReadBlobs(g.ctx, small, g.limits.RenderMaxBytes, func(oid string, data []byte) error {
			contents[oid] = string(data)
			return nil
		}); err != nil {
			return err
		}
	}
	for _, ch := range c.Changes {
		sum := sha1.Sum([]byte(ch.Path))
		fc := FileChange{Status: ch.Status, Path: ch.Path, Anchor: "diff-" + hex.EncodeToString(sum[:8]),
			Added: ch.Added, Deleted: ch.Deleted, Binary: ch.Added < 0}
		if !fc.Binary {
			d.Added += ch.Added
			d.Deleted += ch.Deleted
		}
		if d.Diffs && c.ChangesKnown {
			g.fillDiff(&fc, ch, contents)
		}
		d.Files = append(d.Files, fc)
	}
	p := g.basePage(rg, def, "commits")
	p.Data = d
	return g.page("commit", rg.routes.Commit(c.OID), p)
}

func (g *gen) fillDiff(fc *FileChange, ch policy.Change, contents map[string]string) {
	if fc.Binary || ch.OldKind == policy.Submodule || ch.NewKind == policy.Submodule {
		fc.Note = g.lang.T("diff_binary")
		return
	}
	oldText, okOld := contents[ch.OldBlob]
	newText, okNew := contents[ch.NewBlob]
	if (ch.OldBlob != "" && !okOld) || (ch.NewBlob != "" && !okNew) {
		fc.Note = g.lang.T("diff_too_large")
		return
	}
	if !render.IsText([]byte(oldText)) || !render.IsText([]byte(newText)) {
		fc.Note = g.lang.T("diff_binary")
		return
	}
	lines, ok := render.Diff(oldText, newText)
	if !ok {
		fc.Note = g.lang.T("diff_too_large")
		return
	}
	if len(lines) == 0 {
		fc.Note = g.lang.T("diff_none")
		return
	}
	for _, l := range lines {
		fc.Lines = append(fc.Lines, DiffLineView{Kind: string(rune(l.Kind)), Text: l.Text, Header: l.Header, Old: l.Old, New: l.New})
	}
}

func (g *gen) genRefLists(rg *repoGen) error {
	p := g.basePage(rg, nil, "branches")
	p.Data = &RefsData{TitleKey: "tab_branches", Refs: rg.view.Branches}
	if err := g.page("refs", rg.routes.Branches(), p); err != nil {
		return err
	}
	if len(rg.view.Tags) == 0 {
		return nil
	}
	p = g.basePage(rg, nil, "tags")
	p.Data = &RefsData{TitleKey: "tab_tags", Refs: rg.view.Tags}
	return g.page("refs", rg.routes.Tags(), p)
}

func (g *gen) genReleases(rg *repoGen) error {
	if !rg.src.Policy.Releases {
		return nil
	}
	var all []*ReleaseView
	for i := range rg.src.Releases {
		rel := &rg.src.Releases[i]
		v := g.releaseView(rg, rel)
		var rf *refGen
		for _, x := range rg.refs {
			if x.src.Kind == policy.Tag && x.src.Public == rel.Tag {
				rf = x
			}
		}
		if rf == nil {
			return fmt.Errorf("release %s has no published tag", rel.Tag)
		}
		v.Body = g.md.Render(rel.Body, linker{g: g, rg: rg, ref: rf})
		all = append(all, v)
		p := g.basePage(rg, nil, "releases")
		p.Data = &ReleasesData{Releases: []*ReleaseView{v}}
		if err := g.page("releases", rg.routes.Release(rel.Tag), p); err != nil {
			return err
		}
	}
	p := g.basePage(rg, nil, "releases")
	p.Data = &ReleasesData{Releases: all}
	return g.page("releases", rg.routes.Releases(), p)
}

func (g *gen) genIndex() error {
	groups := map[string]*RepoGroup{}
	var owners []string
	for _, rg := range g.repos {
		v := rg.view
		s := RepoSummary{HomeURL: v.HomeURL, Name: v.Name, Description: v.Description,
			Archived: v.Archived, Topics: v.Topics}
		if len(v.Languages) > 0 && v.Languages[0].Name != "Other" {
			l := v.Languages[0]
			s.Language = &l
		}
		if def := rg.defaultRef(); def != nil {
			if c := rg.src.Commits[def.src.Commit]; c != nil {
				s.Updated = g.date(rg, c.Date)
				s.sortKey = c.Date.UTC().Format(time.RFC3339)
			}
		}
		grp, ok := groups[v.Owner]
		if !ok {
			grp = &RepoGroup{Owner: v.Owner}
			groups[v.Owner] = grp
			owners = append(owners, v.Owner)
		}
		grp.Repos = append(grp.Repos, s)
	}
	sort.Strings(owners)
	d := &IndexData{}
	for _, o := range owners {
		grp := groups[o]
		sort.SliceStable(grp.Repos, func(i, j int) bool {
			if grp.Repos[i].sortKey != grp.Repos[j].sortKey {
				return grp.Repos[i].sortKey > grp.Repos[j].sortKey
			}
			return grp.Repos[i].Name < grp.Repos[j].Name
		})
		d.Groups = append(d.Groups, *grp)
	}
	if err := g.page("index", route{}, &Page{Data: d, Canonical: g.canonical(route{})}); err != nil {
		return err
	}
	if err := g.page("notfound", nil, &Page{}); err != nil {
		return err
	}
	if err := g.w.write("robots.txt", []byte(g.robots())); err != nil {
		return err
	}
	return g.w.write("sitemap.xml", g.sitemap())
}

func (g *gen) robots() string {
	if g.cfg.Site.Robots == "noindex" {
		return "User-agent: *\nDisallow: /\n"
	}
	var b strings.Builder
	b.WriteString("User-agent: *\n")
	for _, p := range []string{"raw", "media", "dl", "archive"} {
		b.WriteString("Disallow: /*/*/" + p + "/\n")
	}
	b.WriteString("Disallow: /*/*.git/\n")
	if base := strings.TrimSuffix(g.cfg.Site.BaseURL, "/"); base != "" {
		b.WriteString("Sitemap: " + base + "/sitemap.xml\n")
	}
	return b.String()
}

func (g *gen) sitemap() []byte {
	var b bytes.Buffer
	b.WriteString(xml.Header)
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	add := func(rt route) {
		if u := g.canonical(rt); u != "" {
			b.WriteString("  <url><loc>")
			_ = xml.EscapeText(&b, []byte(u))
			b.WriteString("</loc></url>\n")
		}
	}
	if g.cfg.Site.Robots != "noindex" {
		add(route{})
		for _, rg := range g.repos {
			add(rg.routes.Home())
		}
	}
	b.WriteString("</urlset>\n")
	return b.Bytes()
}
