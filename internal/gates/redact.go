// SPDX-License-Identifier: AGPL-3.0-or-later

package gates

import (
	"regexp"
	"strings"

	"fpp/internal/policy"
)

// emailRe matches an email address, optionally in angle brackets with the
// whitespace before them ("Name <a@b.c>" → "Name").
var emailRe = regexp.MustCompile(`(?i)(\s*<\s*)?([a-z0-9._%+\-]+@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)(\s*>)?`)

// EmailPlaceholder replaces a bare email address.
const EmailPlaceholder = "[email]"

// Redactor removes email addresses from published text (commit and tag
// messages, trailers such as Co-authored-by and Signed-off-by, names,
// release notes, repo metadata). Addresses in public stay.
type Redactor struct {
	public map[string]bool
}

// NewRedactor returns a redactor exempting the given addresses.
func NewRedactor(public []string) *Redactor {
	r := &Redactor{public: map[string]bool{}}
	for _, e := range public {
		r.public[strings.ToLower(e)] = true
	}
	return r
}

// Text redacts s and returns the number of addresses removed.
func (r *Redactor) Text(s string) (string, int) {
	n := 0
	out := emailRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := emailRe.FindStringSubmatch(m)
		if r.public[strings.ToLower(sub[2])] {
			return m
		}
		n++
		if sub[1] != "" && sub[3] != "" {
			return "" // "Name <a@b.c>" → "Name"
		}
		return sub[1] + EmailPlaceholder + sub[3]
	})
	return out, n
}

// Set redacts every free-text field of the publish set in place and returns
// the number of addresses removed.
func (r *Redactor) Set(set *policy.Set) int {
	n := 0
	red := func(s *string) {
		out, k := r.Text(*s)
		*s = out
		n += k
	}
	for _, repo := range set.Repos {
		red(&repo.Meta.Description)
		red(&repo.Meta.Website)
		for i := range repo.Meta.Topics {
			red(&repo.Meta.Topics[i])
		}
		for _, ref := range repo.Refs {
			if ref.TagInfo != nil {
				red(&ref.TagInfo.Tagger)
				red(&ref.TagInfo.Message)
			}
		}
		for _, c := range repo.Commits {
			red(&c.Author)
			red(&c.Message)
		}
		for i := range repo.Releases {
			red(&repo.Releases[i].Name)
			red(&repo.Releases[i].Body)
		}
	}
	return n
}
