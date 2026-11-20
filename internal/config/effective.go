// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import "time"

// DefaultBranch is the placeholder for the repo's default branch.
const DefaultBranch = "@default"

// BuiltinExclude always applies; config can only add to it.
var BuiltinExclude = []string{
	"**/.env*",
	"**/*.pem",
	"**/*.key",
	"**/id_rsa*",
	"**/id_dsa*",
	"**/id_ecdsa*",
	"**/id_ed25519*",
	"**/*.kdbx",
	"**/*.p12",
	"**/*.pfx",
	"**/.netrc",
	"**/.git-credentials",
	"**/.htpasswd",
}

// Effective is a fully resolved per-repo policy with no inherited fields.
type Effective struct {
	Source      string
	Slug        string
	Branches    []RefSpec
	TagInclude  []string
	TagLatest   int
	MaxCommits  int
	Diffs       bool
	Releases    bool
	Assets      bool
	Prereleases bool
	Archives    bool
	Clone       bool
	Authors     string
	Dates       string
	Exclude     []string
}

// Built-in secure defaults.
func builtin() Effective {
	return Effective{
		Branches:   []RefSpec{{Name: DefaultBranch}},
		MaxCommits: 10,
		Archives:   true,
		Clone:      true,
		Authors:    "names",
		Dates:      "day",
	}
}

// DefaultLimits apply to any zero-valued limit.
var DefaultLimits = Limits{
	RenderMaxBytes:       1 << 20,
	RawMaxBytes:          20 << 20,
	MaxFilesPerRef:       20000,
	MaxSiteBytes:         2 << 30,
	PerFileRenderTimeout: 2 * time.Second,
}

func (e *Effective) apply(p Policy) {
	if p.Branches != nil {
		e.Branches = p.Branches
	}
	if p.Tags != nil {
		if p.Tags.Include != nil {
			e.TagInclude = p.Tags.Include
		}
		if p.Tags.Latest != nil {
			e.TagLatest = *p.Tags.Latest
		}
	}
	if p.History != nil && p.History.MaxCommits != nil {
		e.MaxCommits = *p.History.MaxCommits
	}
	setBool(&e.Diffs, p.Diffs)
	setBool(&e.Archives, p.Archives)
	setBool(&e.Clone, p.Clone)
	if p.Releases != nil {
		setBool(&e.Releases, p.Releases.Enabled)
		setBool(&e.Assets, p.Releases.Assets)
		setBool(&e.Prereleases, p.Releases.Prereleases)
	}
	if p.Authors != nil {
		e.Authors = *p.Authors
	}
	if p.Dates != nil {
		e.Dates = *p.Dates
	}
	e.Exclude = append(e.Exclude, p.Exclude...)
}

func setBool(dst *bool, src *bool) {
	if src != nil {
		*dst = *src
	}
}

// Effective resolves repo i against publish.defaults and the built-ins.
func (c *Config) Effective(i int) Effective {
	r := c.Publish.Repos[i]
	e := builtin()
	e.Exclude = append([]string(nil), BuiltinExclude...)
	e.apply(c.Publish.Defaults)
	e.apply(r.Policy)
	e.Source = r.Source
	e.Slug = r.Slug
	if e.Slug == "" {
		e.Slug = r.Source
	}
	return e
}

// EffectiveLimits fills zero-valued limits with DefaultLimits.
func (c *Config) EffectiveLimits() Limits {
	l := c.Gates.Limits
	d := DefaultLimits
	if l.RenderMaxBytes == 0 {
		l.RenderMaxBytes = d.RenderMaxBytes
	}
	if l.RawMaxBytes == 0 {
		l.RawMaxBytes = d.RawMaxBytes
	}
	if l.MaxFilesPerRef == 0 {
		l.MaxFilesPerRef = d.MaxFilesPerRef
	}
	if l.MaxSiteBytes == 0 {
		l.MaxSiteBytes = d.MaxSiteBytes
	}
	if l.PerFileRenderTimeout == 0 {
		l.PerFileRenderTimeout = d.PerFileRenderTimeout
	}
	return l
}

// SecretScanEnabled defaults to true.
func (c *Config) SecretScanEnabled() bool {
	return c.Gates.SecretScan.Enabled == nil || *c.Gates.SecretScan.Enabled
}

// HasDeploy reports whether the config has a deploy section. Without one,
// only `fpp apply -no-deploy` can run.
func (c *Config) HasDeploy() bool {
	return c.Deploy != (Deploy{})
}

// KeepReleases defaults to 5.
func (c *Config) KeepReleases() int {
	if c.Deploy.KeepReleases == 0 {
		return 5
	}
	return c.Deploy.KeepReleases
}

// DeployPort defaults to 22.
func (c *Config) DeployPort() int {
	if c.Deploy.Port == 0 {
		return 22
	}
	return c.Deploy.Port
}
