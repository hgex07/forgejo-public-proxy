// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

var (
	// Owner and repo name segments (Forgejo names and public slugs). Leading
	// '.' and '-' are rejected so a segment can never be "..", a dotfile or
	// look like a command-line option.
	segmentRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	// Public ref names used in URLs.
	publicRefRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	credentialRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	themeRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	hostnameRe    = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	sshUserRe     = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	forgejoUserRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
)

// Top-level URL segments the site itself uses; a slug owner may not take them.
var reservedTop = map[string]bool{
	"robots.txt": true, "sitemap.xml": true, "404.html": true,
	"favicon.ico": true, "index.html": true, "build.txt": true,
}

const (
	maxSegmentLen  = 100
	maxCommitsCap  = 1000
	maxTagLatest   = 100
	maxKeepRelease = 50
)

type validator struct {
	errs  []error
	warns []string
}

func (v *validator) errf(field, format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf("%s: %s", field, fmt.Sprintf(format, args...)))
}

func (v *validator) warnf(field, format string, args ...any) {
	v.warns = append(v.warns, fmt.Sprintf("%s: %s", field, fmt.Sprintf(format, args...)))
}

// Validate checks the whole config and returns all problems at once.
func (c *Config) Validate() (warnings []string, err error) {
	v := &validator{}
	c.validateSite(v)
	c.validateForgejo(v)
	c.validatePublish(v)
	c.validateGates(v)
	c.validateDeploy(v)
	return v.warns, errors.Join(v.errs...)
}

func (c *Config) validateSite(v *validator) {
	s := c.Site
	if strings.TrimSpace(s.Title) == "" {
		v.errf("site.title", "required")
	}
	if u, ok := checkURL(v, "site.base_url", s.BaseURL); ok {
		if u.Scheme != "https" {
			v.errf("site.base_url", "must use https")
		}
		if u.Path != "" && u.Path != "/" {
			v.errf("site.base_url", "must not have a path (site is served at the root)")
		}
	}
	if s.Theme != "" && !themeRe.MatchString(s.Theme) {
		v.errf("site.theme", "%q: must match %s", s.Theme, themeRe)
	}
	switch s.Language {
	case "", "en", "es":
	default:
		v.errf("site.language", "%q: must be en or es", s.Language)
	}
	switch s.Robots {
	case "", "index", "noindex":
	default:
		v.errf("site.robots", "%q: must be index or noindex", s.Robots)
	}
	for i, h := range s.AllowedImageHosts {
		if !hostnameRe.MatchString(h) {
			v.errf(fmt.Sprintf("site.allowed_image_hosts[%d]", i), "%q: must be a lowercase hostname (no scheme, port or wildcard)", h)
		}
	}
	if len(s.AllowedImageHosts) > 0 {
		v.warnf("site.allowed_image_hosts", "external images let those hosts see visitor IPs")
	}
}

func (c *Config) validateForgejo(v *validator) {
	f := c.Forgejo
	api, apiOK := checkURL(v, "forgejo.api_url", f.APIURL)
	root, rootOK := checkURL(v, "forgejo.root_url", f.RootURL)
	for _, x := range []struct {
		name string
		u    *url.URL
		ok   bool
	}{{"forgejo.api_url", api, apiOK}, {"forgejo.root_url", root, rootOK}} {
		if !x.ok {
			continue
		}
		if x.u.Scheme != "http" && x.u.Scheme != "https" {
			v.errf(x.name, "scheme must be http or https")
		}
		if base, err := url.Parse(c.Site.BaseURL); err == nil && base.Hostname() != "" &&
			strings.EqualFold(base.Hostname(), x.u.Hostname()) {
			v.errf(x.name, "host must differ from site.base_url (the public site must never be the Forgejo host)")
		}
	}
	if apiOK && api.Scheme == "http" && !isLoopback(api.Hostname()) {
		v.warnf("forgejo.api_url", "plain http to a non-loopback host sends the token unencrypted")
	}
	if f.User == "" {
		v.errf("forgejo.user", "required")
	} else if !forgejoUserRe.MatchString(f.User) {
		v.errf("forgejo.user", "%q: invalid username", f.User)
	}
	checkCredential(v, "forgejo.token.credential", f.Token)
	if len(f.CanaryRepos) == 0 {
		v.errf("forgejo.canary_repos", "at least one canary repo is required (docs/SETUP.md §1)")
	} else if len(f.CanaryRepos) < 2 {
		v.warnf("forgejo.canary_repos", "only one canary; add a public one too, to prove the Restricted flag")
	}
	seen := map[string]bool{}
	for i, r := range f.CanaryRepos {
		field := fmt.Sprintf("forgejo.canary_repos[%d]", i)
		checkRepoPath(v, field, r)
		k := strings.ToLower(r)
		if seen[k] {
			v.errf(field, "%q listed twice", r)
		}
		seen[k] = true
	}
}

func (c *Config) validatePublish(v *validator) {
	checkPolicyShape(v, "publish.defaults", c.Publish.Defaults)
	if len(c.Publish.Repos) == 0 {
		v.warnf("publish.repos", "no repos listed; the site will be empty")
	}
	canaries := map[string]bool{}
	for _, r := range c.Forgejo.CanaryRepos {
		canaries[strings.ToLower(r)] = true
	}
	sources := map[string]int{}
	slugs := map[string]int{}
	for i, r := range c.Publish.Repos {
		field := fmt.Sprintf("publish.repos[%d]", i)
		checkRepoPath(v, field+".source", r.Source)
		src := strings.ToLower(r.Source)
		if j, dup := sources[src]; dup {
			v.errf(field+".source", "%q already listed at publish.repos[%d]", r.Source, j)
		}
		sources[src] = i
		if canaries[src] {
			v.errf(field+".source", "%q is a canary repo; canaries must never be published", r.Source)
		}
		if r.Slug != "" {
			checkRepoPath(v, field+".slug", r.Slug)
		}
		checkPolicyShape(v, field, r.Policy)

		e := c.Effective(i)
		owner, _, _ := strings.Cut(e.Slug, "/")
		if strings.HasPrefix(owner, "_") || reservedTop[strings.ToLower(owner)] {
			v.errf(field+".slug", "%q: owner segment is reserved by the site (no leading '_', robots.txt, …)", e.Slug)
		}
		// Case-insensitive: two slugs differing only in case would collide on
		// case-insensitive filesystems and caches.
		sl := strings.ToLower(e.Slug)
		if j, dup := slugs[sl]; dup {
			v.errf(field, "public slug %q collides with publish.repos[%d]", e.Slug, j)
		}
		slugs[sl] = i
		c.checkEffective(v, field, e)
	}
}

// checkPolicyShape validates fields that are meaningful on their own.
func checkPolicyShape(v *validator, field string, p Policy) {
	for j, b := range p.Branches {
		checkRefSpec(v, fmt.Sprintf("%s.branches[%d]", field, j), b)
	}
	if p.Tags != nil {
		for j, g := range p.Tags.Include {
			if _, err := path.Match(g, ""); err != nil || g == "" || strings.Contains(g, "/") {
				v.errf(fmt.Sprintf("%s.tags.include[%d]", field, j), "%q: invalid glob (no '/', path.Match syntax)", g)
			}
		}
		if p.Tags.Latest != nil && (*p.Tags.Latest < 0 || *p.Tags.Latest > maxTagLatest) {
			v.errf(field+".tags.latest", "must be between 0 and %d", maxTagLatest)
		}
	}
	if p.History != nil && p.History.MaxCommits != nil {
		if n := *p.History.MaxCommits; n < 0 || n > maxCommitsCap {
			v.errf(field+".history.max_commits", "must be between 0 and %d", maxCommitsCap)
		}
	}
	if p.Authors != nil && *p.Authors != "names" && *p.Authors != "hidden" {
		v.errf(field+".authors", "%q: must be names or hidden", *p.Authors)
	}
	if p.Dates != nil && *p.Dates != "day" && *p.Dates != "exact" {
		v.errf(field+".dates", "%q: must be day or exact", *p.Dates)
	}
	for j, g := range p.Exclude {
		if g == "" || !doublestar.ValidatePattern(g) || strings.HasPrefix(g, "/") {
			v.errf(fmt.Sprintf("%s.exclude[%d]", field, j), "%q: invalid glob (doublestar syntax, relative)", g)
		}
	}
}

// checkEffective validates the resolved policy of one repo.
func (c *Config) checkEffective(v *validator, field string, e Effective) {
	if len(e.Branches) == 0 && len(e.TagInclude) == 0 {
		v.errf(field, "publishes no refs (empty branches and no tags)")
	}
	names := map[string]bool{}
	for _, b := range e.Branches {
		n := strings.ToLower(b.PublicName())
		if names[n] {
			v.errf(field+".branches", "public ref name %q used twice", b.PublicName())
		}
		names[n] = true
	}
	if len(e.TagInclude) > 0 && e.TagLatest == 0 {
		v.errf(field+".tags.latest", "must be ≥1 when tags.include is set (every tag publishes a full tree)")
	}
	if e.Assets && !e.Releases {
		v.warnf(field+".releases.assets", "has no effect while releases.enabled is false")
	}
	if e.Prereleases && !e.Releases {
		v.warnf(field+".releases.prereleases", "has no effect while releases.enabled is false")
	}
	if e.Releases {
		v.warnf(field+".releases", "enabling releases publishes each release tag's tree and notes")
	}
	if e.Diffs && !c.SecretScanEnabled() {
		v.errf(field+".diffs", "diffs require gates.secret_scan (removed lines can reveal old secrets)")
	}
}

func checkRefSpec(v *validator, field string, r RefSpec) {
	switch {
	case r.Name == "":
		v.errf(field, "name required")
	case r.Name == DefaultBranch:
	case !validGitRef(r.Name):
		v.errf(field, "%q: not a valid branch name", r.Name)
	case r.As == "" && !publicRefRe.MatchString(r.Name):
		v.errf(field, "%q: names outside %s need an alias: {name: %q, as: <url-safe name>}", r.Name, publicRefRe, r.Name)
	}
	if r.As != "" && !publicRefRe.MatchString(r.As) {
		v.errf(field+".as", "%q: must match %s", r.As, publicRefRe)
	}
	if strings.HasSuffix(r.PublicName(), ".lock") {
		v.errf(field, "%q: public name must not end in .lock", r.PublicName())
	}
}

// validGitRef is a conservative subset of git check-ref-format for a branch.
func validGitRef(s string) bool {
	if s == "" || len(s) > 200 || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "/") ||
		strings.HasSuffix(s, "/") || strings.HasSuffix(s, ".") || strings.HasSuffix(s, ".lock") ||
		strings.Contains(s, "..") || strings.Contains(s, "//") || strings.Contains(s, "@{") || s == "@" {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(" ~^:?*[\\", r) {
			return false
		}
	}
	for _, seg := range strings.Split(s, "/") {
		if strings.HasPrefix(seg, ".") {
			return false
		}
	}
	return true
}

func (c *Config) validateGates(v *validator) {
	g := c.Gates
	if !c.SecretScanEnabled() {
		v.warnf("gates.secret_scan.enabled", "secret scanning is OFF; published content is not checked for secrets")
	}
	if g.SecretScan.Baseline != "" && !filepath.IsAbs(g.SecretScan.Baseline) {
		v.errf("gates.secret_scan.baseline", "must be an absolute path")
	}
	for i, p := range g.LeakPatterns {
		field := fmt.Sprintf("gates.leak_patterns[%d]", i)
		if p.Pattern == "" {
			v.errf(field+".pattern", "required")
		} else if _, err := regexp.Compile(p.Pattern); err != nil {
			v.errf(field+".pattern", "%v", err)
		}
		if p.Action != "block" && p.Action != "warn" {
			v.errf(field+".action", "%q: must be block or warn", p.Action)
		}
	}
	for i, e := range g.PublicEmails {
		if at := strings.IndexByte(e, '@'); at <= 0 || at == len(e)-1 || strings.ContainsAny(e, " <>") {
			v.errf(fmt.Sprintf("gates.public_emails[%d]", i), "%q: not an email address", e)
		}
	}
	l := g.Limits
	for _, x := range []struct {
		name string
		n    int64
	}{
		{"render_max_bytes", l.RenderMaxBytes}, {"raw_max_bytes", l.RawMaxBytes},
		{"max_files_per_ref", int64(l.MaxFilesPerRef)}, {"max_site_bytes", l.MaxSiteBytes},
		{"per_file_render_timeout", int64(l.PerFileRenderTimeout)},
	} {
		if x.n < 0 {
			v.errf("gates.limits."+x.name, "must not be negative")
		}
	}
	el := c.EffectiveLimits()
	if el.RenderMaxBytes > el.RawMaxBytes {
		v.errf("gates.limits.render_max_bytes", "must not exceed raw_max_bytes")
	}
	if el.RawMaxBytes > el.MaxSiteBytes {
		v.errf("gates.limits.raw_max_bytes", "must not exceed max_site_bytes")
	}
}

func (c *Config) validateDeploy(v *validator) {
	if !c.HasDeploy() {
		return // optional: `fpp apply -no-deploy` and serve the staged site yourself
	}
	d := c.Deploy
	user, host, ok := strings.Cut(d.Target, "@")
	switch {
	case d.Target == "":
		v.errf("deploy.target", "required (user@host)")
	case !ok || !sshUserRe.MatchString(user):
		v.errf("deploy.target", "%q: must be user@host", d.Target)
	case net.ParseIP(host) == nil && !hostnameRe.MatchString(host):
		v.errf("deploy.target", "%q: host must be an IP address or hostname (no port)", d.Target)
	}
	if d.Port < 0 || d.Port > 65535 {
		v.errf("deploy.port", "%d: must be a TCP port", d.Port)
	}
	checkCredential(v, "deploy.ssh_key.credential", d.SSHKey)
	if d.KnownHosts == "" {
		v.errf("deploy.known_hosts", "required (host key pinning)")
	} else if !filepath.IsAbs(d.KnownHosts) {
		v.errf("deploy.known_hosts", "must be an absolute path")
	}
	if d.KeepReleases != 0 && (d.KeepReleases < 2 || d.KeepReleases > maxKeepRelease) {
		v.errf("deploy.keep_releases", "must be between 2 and %d (rollback needs a previous release)", maxKeepRelease)
	}
}

func checkCredential(v *validator, field string, c Credential) {
	if c.Credential == "" {
		v.errf(field, "required (systemd LoadCredential= name; secrets are never inline)")
	} else if !credentialRe.MatchString(c.Credential) {
		v.errf(field, "%q: must be a credential name, not a path or secret", c.Credential)
	}
}

func checkRepoPath(v *validator, field, s string) {
	owner, repo, ok := strings.Cut(s, "/")
	if !ok || strings.Contains(repo, "/") {
		v.errf(field, "%q: must be owner/repo", s)
		return
	}
	for _, seg := range []string{owner, repo} {
		if !segmentRe.MatchString(seg) || len(seg) > maxSegmentLen || strings.HasSuffix(seg, ".git") {
			v.errf(field, "%q: segment %q must match %s, ≤%d chars, no .git suffix", s, seg, segmentRe, maxSegmentLen)
		}
	}
}

func checkURL(v *validator, field, raw string) (*url.URL, bool) {
	if raw == "" {
		v.errf(field, "required")
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || !u.IsAbs() {
		v.errf(field, "%q: must be an absolute URL", raw)
		return nil, false
	}
	if u.User != nil {
		v.errf(field, "must not contain credentials")
		return nil, false
	}
	if u.RawQuery != "" || u.Fragment != "" {
		v.errf(field, "must not have a query or fragment")
		return nil, false
	}
	return u, true
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
