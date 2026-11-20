// SPDX-License-Identifier: AGPL-3.0-or-later

// Package render turns published content into HTML fragments: sanitized
// markdown, syntax-highlighted code and diffs.
//
// This file is the only place in the module allowed to produce
// template.HTML (enforced by scripts/check-template-html.sh). Everything
// that reaches it has been escaped by this package or sanitized by
// bluemonday.
package render

import (
	"html/template"
	"strings"
)

// Safe is an HTML fragment produced by this package. Other packages cannot
// construct one with arbitrary content: the field is unexported.
type Safe struct{ h string }

// HTML returns the fragment for html/template.
func (s Safe) HTML() template.HTML { return template.HTML(s.h) } //nolint:gosec // see package doc

// IsZero reports whether the fragment is empty.
func (s Safe) IsZero() bool { return s.h == "" }

// String returns the raw markup (for tests and output lint).
func (s Safe) String() string { return s.h }

// sanitized wraps bluemonday output.
func sanitized(s string) Safe { return Safe{h: s} }

// escaped builds a fragment from parts the caller has already escaped with
// escape(); it exists so the call sites are easy to audit.
func escaped(parts ...string) Safe { return Safe{h: strings.Join(parts, "")} }

func escape(s string) string { return template.HTMLEscapeString(s) }
