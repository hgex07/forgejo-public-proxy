// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gates runs the safety gates over the exact content that will be
// published: email redaction, the secret scan
// (gitleaks), the built-in leak rules (token, Forgejo host names), the
// configured leak_patterns and bidi detection.
//
// It sees only the publish set, so it scans exactly what the renderer will
// read: file contents, paths, both sides of published diffs, commit and tag
// messages, author names, release notes and repo metadata. Any block
// finding fails the publish closed (I7).
package gates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	glconfig "github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"

	"fpp/internal/config"
	"fpp/internal/policy"
	"fpp/internal/render"
)

// Finding is one gate hit.
type Finding struct {
	Repo    string // public slug
	Where   string // human-readable location
	Rule    string // "secret:<gitleaks rule>", "token", "forgejo-host", "leak_patterns[i]", "bidi"
	Action  Action
	Excerpt string // safe to print: secrets are masked, the token never shown
	// Fingerprint identifies a secret-scan finding for the baseline.
	Fingerprint string
	// Baselined is the reviewed reason when the baseline downgraded a
	// secret-scan finding to a warning.
	Baselined string
}

// Report is the outcome of Run.
type Report struct {
	Findings []Finding
	// Redacted counts email addresses removed from published text.
	Redacted int
	// Blobs and Bytes count the file contents scanned.
	Blobs int
	Bytes int64
	// SecretScan is false when gates.secret_scan.enabled is off.
	SecretScan bool
}

// Blocked lists the findings that block publishing.
func (r *Report) Blocked() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Action == Block {
			out = append(out, f)
		}
	}
	return out
}

// Options configure Run.
type Options struct {
	Config *config.Config
	// Token is the Forgejo token value; it must never be published.
	Token string
	// Baseline maps reviewed secret-scan fingerprints to their reason.
	Baseline map[string]string
}

const (
	RuleBidi     = "bidi"
	secretPrefix = "secret:"
	// fingerprintLen is the length of a finding fingerprint (hex).
	fingerprintLen = 16
)

var quietGitleaks sync.Once

// Run redacts the set in place, then scans it.
func Run(ctx context.Context, set *policy.Set, o Options) (*Report, error) {
	rep := &Report{SecretScan: o.Config.SecretScanEnabled()}
	rep.Redacted = NewRedactor(o.Config.Gates.PublicEmails).Set(set)
	m, err := NewMatcher(o.Config, o.Token)
	if err != nil {
		return nil, err
	}
	s := &scanner{m: m, rep: rep, baseline: o.Baseline, limits: o.Config.EffectiveLimits(), seen: map[string]bool{}}
	if rep.SecretScan {
		// gitleaks logs through a global zerolog logger; findings must
		// only ever leave through the Report.
		quietGitleaks.Do(func() { logging.Logger = zerolog.Nop() })
		if s.det, err = detect.NewDetectorDefaultConfig(); err != nil {
			return nil, fmt.Errorf("gitleaks: %w", err)
		}
		// Repo content must not be able to silence the scan.
		s.det.IgnoreGitleaksAllow = true
		s.det.MaxDecodeDepth = 5
		dropPathAllowlists(&s.det.Config)
	}
	for _, r := range set.Repos {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.repo = r
		if err := s.scanRepo(ctx); err != nil {
			return nil, fmt.Errorf("gates: %s: %w", r.Slug, err)
		}
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Action != b.Action {
			return a.Action == Block
		}
		return a.Repo < b.Repo
	})
	return rep, nil
}

type scanner struct {
	m        *Matcher
	det      *detect.Detector
	rep      *Report
	baseline map[string]string
	limits   config.Limits
	repo     *policy.Repo
	seen     map[string]bool
}

func (s *scanner) scanRepo(ctx context.Context) error {
	r := s.repo
	s.text("repo description", "", r.Meta.Description)
	s.text("repo website", "", r.Meta.Website)
	s.text("repo topics", "", strings.Join(r.Meta.Topics, "\n"))
	for _, ref := range r.Refs {
		s.text(fmt.Sprintf("%s name", ref.Kind), "", ref.Public)
		if ref.TagInfo != nil {
			s.text("tag "+ref.Public+" tagger", "", ref.TagInfo.Tagger)
			s.text("tag "+ref.Public+" message", "", ref.TagInfo.Message)
		}
	}
	for _, rel := range r.Releases {
		s.text("release "+rel.Tag+" title", "", rel.Name)
		s.text("release "+rel.Tag+" notes", "", rel.Body)
	}

	oids := make([]string, 0, len(r.Commits))
	for oid := range r.Commits {
		oids = append(oids, oid)
	}
	sort.Strings(oids)
	paths := map[string]bool{}
	for _, oid := range oids {
		c := r.Commits[oid]
		s.text(fmt.Sprintf("commit %.10s author", oid), "", c.Author)
		s.text(fmt.Sprintf("commit %.10s message", oid), "", c.Message)
		for _, ch := range c.Changes {
			paths[ch.Path] = true
		}
	}

	// Blob contents: every published file once (located at its first
	// appearance), then, with diffs on, both sides of every published diff.
	where := map[string]string{} // oid → location
	fpPath := map[string]string{}
	var blobs []string
	add := func(oid, loc, p string) {
		if oid == "" {
			return
		}
		if _, ok := where[oid]; !ok {
			where[oid], fpPath[oid] = loc, p
			blobs = append(blobs, oid)
		}
	}
	for _, ref := range r.Refs {
		for _, f := range ref.Files {
			paths[f.Path] = true
			if f.Kind != policy.Submodule {
				add(f.OID, ref.Public+":"+f.Path, f.Path)
			}
		}
	}
	var pathList []string
	for p := range paths {
		pathList = append(pathList, p)
	}
	sort.Strings(pathList)
	for _, p := range pathList {
		s.text("path "+p, "", p)
	}

	readMax := s.limits.RawMaxBytes
	if r.Policy.Diffs {
		var diffBlobs []string
		for _, oid := range oids {
			for _, ch := range r.Commits[oid].Changes {
				for _, b := range []string{ch.OldBlob, ch.NewBlob} {
					if b != "" {
						if _, ok := where[b]; !ok {
							diffBlobs = append(diffBlobs, b)
						}
						add(b, fmt.Sprintf("commit %.10s diff %s", oid, ch.Path), ch.Path)
					}
				}
			}
		}
		// Diffs are rendered only up to render_max_bytes; larger sides
		// are never published, so they are not scanned either.
		sizes, err := r.BlobSizes(ctx, diffBlobs)
		if err != nil {
			return err
		}
		big := map[string]bool{}
		for oid, n := range sizes {
			if n > s.limits.RenderMaxBytes {
				big[oid] = true
			}
		}
		kept := blobs[:0]
		for _, b := range blobs {
			if !big[b] {
				kept = append(kept, b)
			}
		}
		blobs = kept
	}
	return r.ReadBlobs(ctx, blobs, readMax, func(oid string, data []byte) error {
		s.rep.Blobs++
		s.rep.Bytes += int64(len(data))
		s.content(where[oid], fpPath[oid], data)
		return nil
	})
}

// text scans a short published string (message, name, path…).
func (s *scanner) text(where, fpPath, v string) {
	if v == "" {
		return
	}
	s.content(where, fpPath, []byte(v))
}

// content scans published bytes.
func (s *scanner) content(where, fpPath string, data []byte) {
	for _, x := range s.m.Find(data) {
		s.add(Finding{Where: withLine(where, data, x.Start), Rule: x.Rule, Action: x.Action, Excerpt: s.m.Display(x, data)})
	}
	if render.IsText(data) && render.HasBidi(data) {
		s.add(Finding{Where: where, Rule: RuleBidi, Action: Warn, Excerpt: "bidirectional control characters (shown with a warning banner)"})
	}
	// Every published blob goes through gitleaks, text or not: a Latin-1
	// config file or a binary with an embedded ASCII key is published as a
	// download, and Go's regexp matches ASCII secrets in invalid UTF-8.
	if s.det == nil {
		return
	}
	//lint:ignore SA1019 Detect only accepts detect.Fragment in v8.
	for _, f := range s.det.Detect(detect.Fragment{Raw: string(data), FilePath: fpPath}) {
		rule := secretPrefix + f.RuleID
		fp := Fingerprint(s.repo.Slug, rule, fpPath, f.Secret)
		fd := Finding{Where: fmt.Sprintf("%s:%d", where, f.StartLine+1), Rule: rule, Action: Block,
			Excerpt: mask(f.Secret), Fingerprint: fp}
		if reason, ok := s.baseline[fp]; ok {
			fd.Action, fd.Baselined = Warn, reason
		}
		s.add(fd)
	}
}

func (s *scanner) add(f Finding) {
	f.Repo = s.repo.Slug
	key := f.Repo + "\x00" + f.Where + "\x00" + f.Rule + "\x00" + f.Excerpt
	if s.seen[key] {
		return
	}
	s.seen[key] = true
	s.rep.Findings = append(s.rep.Findings, f)
}

// withLine appends the 1-based line of offset off when data has several lines.
func withLine(where string, data []byte, off int) string {
	if !strings.ContainsRune(string(data), '\n') {
		return where
	}
	return fmt.Sprintf("%s:%d", where, 1+strings.Count(string(data[:off]), "\n"))
}

// Fingerprint identifies a secret finding independently of the ref, commit
// or line it appears at: the same secret in the same file matches the same
// baseline entry everywhere.
func Fingerprint(slug, rule, path, secret string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{slug, rule, path, secret}, "\x00")))
	return hex.EncodeToString(h[:])[:fingerprintLen]
}

// mask shows only the start of a secret.
func mask(secret string) string {
	r := []rune(secret)
	if len(r) < 12 {
		return fmt.Sprintf("…(%d chars)", len(r))
	}
	return fmt.Sprintf("%s…(%d chars)", excerpt(string(r[:4]), 4), len(r))
}

// dropPathAllowlists removes every path-based exemption from the gitleaks
// config. The default config skips whole paths (node_modules/, vendor/,
// bootstrap*.js, lock files, …), but fpp publishes exactly those bytes, so
// the path a repo chose must never decide whether its content is scanned.
// An allowlist that also has regexes or stopwords keeps them when its
// criteria are OR'ed; an AND allowlist that needs a path match is dropped,
// which can only add findings.
func dropPathAllowlists(c *glconfig.Config) {
	c.Allowlists = withoutPaths(c.Allowlists)
	for id, r := range c.Rules {
		r.Allowlists = withoutPaths(r.Allowlists)
		c.Rules[id] = r
	}
}

func withoutPaths(in []*glconfig.Allowlist) []*glconfig.Allowlist {
	var out []*glconfig.Allowlist
	for _, a := range in {
		if len(a.Paths) == 0 {
			out = append(out, a)
			continue
		}
		if a.MatchCondition == glconfig.AllowlistMatchAnd {
			continue
		}
		b := &glconfig.Allowlist{
			Description:    a.Description,
			MatchCondition: a.MatchCondition,
			Commits:        a.Commits,
			RegexTarget:    a.RegexTarget,
			Regexes:        a.Regexes,
			StopWords:      a.StopWords,
		}
		if b.Validate() == nil { // fails only when nothing but paths was left
			out = append(out, b)
		}
	}
	return out
}
