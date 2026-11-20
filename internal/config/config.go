// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config defines the fpp configuration schema, decodes it strictly and
// validates it. deploy/builder/config.example.yaml documents every option.
//
// Strictness rules:
//   - unknown keys, duplicate keys and multiple YAML documents are errors;
//   - secrets are never accepted inline: the token and the deploy key are
//     referenced by systemd credential name only;
//   - every per-repo setting falls back to publish.defaults, which falls back to
//     the built-in secure defaults (Defaults()).
package config

import "time"

// MaxConfigBytes bounds how much of the config file is read.
const MaxConfigBytes = 1 << 20

// Config is the top-level document as written in config.yaml.
type Config struct {
	Site    Site    `yaml:"site"`
	Forgejo Forgejo `yaml:"forgejo"`
	Publish Publish `yaml:"publish"`
	Gates   Gates   `yaml:"gates"`
	Deploy  Deploy  `yaml:"deploy"`
}

type Site struct {
	Title             string   `yaml:"title"`
	BaseURL           string   `yaml:"base_url"`
	Description       string   `yaml:"description"`
	Theme             string   `yaml:"theme"`
	Language          string   `yaml:"language"` // en | es (default en)
	Robots            string   `yaml:"robots"`   // index | noindex
	AllowedImageHosts []string `yaml:"allowed_image_hosts"`
}

type Forgejo struct {
	APIURL      string     `yaml:"api_url"`
	RootURL     string     `yaml:"root_url"`
	User        string     `yaml:"user"`
	Token       Credential `yaml:"token"`
	CanaryRepos []string   `yaml:"canary_repos"`
}

// Credential names a systemd LoadCredential= entry. The secret itself never
// appears in the config file.
type Credential struct {
	Credential string `yaml:"credential"`
}

type Publish struct {
	Defaults Policy      `yaml:"defaults"`
	Repos    []RepoEntry `yaml:"repos"`
}

// RepoEntry is one allowlisted repository. Policy fields are inlined so a repo
// entry can override any default.
type RepoEntry struct {
	Source string `yaml:"source"` // Forgejo owner/repo
	Slug   string `yaml:"slug"`   // public owner/repo alias; empty = same as Source
	Policy `yaml:",inline"`
}

// Policy is a partial exposure policy. Nil means "inherit".
type Policy struct {
	Branches []RefSpec       `yaml:"branches"`
	Tags     *TagsPolicy     `yaml:"tags"`
	History  *HistoryPolicy  `yaml:"history"`
	Diffs    *bool           `yaml:"diffs"`
	Releases *ReleasesPolicy `yaml:"releases"`
	Archives *bool           `yaml:"archives"`
	Clone    *bool           `yaml:"clone"`   // static snapshot repo for git clone over HTTPS
	Authors  *string         `yaml:"authors"` // names | hidden
	Dates    *string         `yaml:"dates"`   // day | exact
	// Exclude globs are additive: built-in denylist + defaults + repo.
	Exclude []string `yaml:"exclude"`
}

type TagsPolicy struct {
	Include []string `yaml:"include"`
	Latest  *int     `yaml:"latest"`
}

type HistoryPolicy struct {
	MaxCommits *int `yaml:"max_commits"`
}

type ReleasesPolicy struct {
	Enabled     *bool `yaml:"enabled"`
	Assets      *bool `yaml:"assets"`
	Prereleases *bool `yaml:"prereleases"`
}

// RefSpec is a branch to publish. In YAML it is either a plain name
// ("main", "@default") or a mapping {name: "feature/x", as: "feature-x"} for
// refs whose names are not URL-safe.
type RefSpec struct {
	Name string `yaml:"name"`
	As   string `yaml:"as"`
}

// PublicName is the name used in URLs.
func (r RefSpec) PublicName() string {
	if r.As != "" {
		return r.As
	}
	return r.Name
}

type Gates struct {
	SecretScan   SecretScan    `yaml:"secret_scan"`
	LeakPatterns []LeakPattern `yaml:"leak_patterns"`
	PublicEmails []string      `yaml:"public_emails"` // exempt from redaction
	Limits       Limits        `yaml:"limits"`
}

type SecretScan struct {
	Enabled  *bool  `yaml:"enabled"`
	Baseline string `yaml:"baseline"`
}

type LeakPattern struct {
	Pattern string `yaml:"pattern"`
	Action  string `yaml:"action"` // block | warn
}

type Limits struct {
	RenderMaxBytes       int64         `yaml:"render_max_bytes"`
	RawMaxBytes          int64         `yaml:"raw_max_bytes"`
	MaxFilesPerRef       int           `yaml:"max_files_per_ref"`
	MaxSiteBytes         int64         `yaml:"max_site_bytes"`
	PerFileRenderTimeout time.Duration `yaml:"per_file_render_timeout"`
}

type Deploy struct {
	Target       string     `yaml:"target"` // user@host
	Port         int        `yaml:"port"`   // SSH port (default 22)
	SSHKey       Credential `yaml:"ssh_key"`
	KnownHosts   string     `yaml:"known_hosts"`
	KeepReleases int        `yaml:"keep_releases"`
}
