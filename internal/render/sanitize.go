// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"regexp"
	"sync"

	"github.com/microcosm-cc/bluemonday"
)

// ContentPrefix is prepended to every id/name from user content so it cannot
// clobber the site's own DOM ids.
const ContentPrefix = "user-content-"

// relExternal is set on every link that leaves the site.
const relExternal = "nofollow noopener noreferrer"

var (
	policyOnce sync.Once
	policy     *bluemonday.Policy
)

// Policy is the strict allowlist for user HTML (README raw HTML, release
// notes). Modeled on the GitHub/Forgejo allowlist.
func Policy() *bluemonday.Policy {
	policyOnce.Do(func() {
		p := bluemonday.UGCPolicy()
		// rel is set by rewrite (external links only).
		p.RequireNoFollowOnLinks(false)
		p.AllowURLSchemes("http", "https", "mailto")
		p.AllowRelativeURLs(true)
		p.RequireParseableURLs(true)
		p.AllowElements("details", "summary", "kbd", "samp", "var", "sub", "sup", "ins", "del", "s")
		p.AllowAttrs("open").OnElements("details")
		p.AllowAttrs("align").Matching(regexp.MustCompile(`^(?i:left|right|center|justify)$`)).
			OnElements("p", "div", "img", "h1", "h2", "h3", "h4", "h5", "h6", "td", "th")
		p.AllowAttrs("width", "height").Matching(regexp.MustCompile(`^[0-9]{1,4}%?$`)).OnElements("img")
		p.AllowAttrs("type").Matching(regexp.MustCompile(`^checkbox$`)).OnElements("input")
		p.AllowAttrs("checked", "disabled").Matching(regexp.MustCompile(`^(|checked|disabled)$`)).OnElements("input")
		p.AllowAttrs("id").Matching(regexp.MustCompile(`^[\pL\pN_.:-]{1,200}$`)).Globally()
		p.AllowAttrs("name").Matching(regexp.MustCompile(`^[\pL\pN_.:-]{1,200}$`)).OnElements("a")
		p.AllowAttrs("rel").Matching(regexp.MustCompile(`^nofollow noopener noreferrer$`)).OnElements("a")
		// Classes only from our highlighter and goldmark's task lists.
		p.AllowAttrs("class").Matching(regexp.MustCompile(`^hl-[a-z0-9]{1,4}$`)).OnElements("span")
		p.AllowAttrs("class").Matching(regexp.MustCompile(`^hl$`)).OnElements("pre")
		p.AllowAttrs("class").Matching(regexp.MustCompile(`^language-[A-Za-z0-9_+#-]{1,40}$`)).OnElements("code")
		p.AllowAttrs("class").Matching(regexp.MustCompile(`^(task-list-item|contains-task-list)$`)).OnElements("li", "ul", "ol")
		policy = p
	})
	return policy
}

// SanitizeHTML runs the allowlist over s.
func SanitizeHTML(s string) string { return Policy().Sanitize(s) }
