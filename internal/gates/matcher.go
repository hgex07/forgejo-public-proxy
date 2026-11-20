// SPDX-License-Identifier: AGPL-3.0-or-later

package gates

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"fpp/internal/config"
)

// Action is what a finding does to the publish.
type Action string

const (
	Block Action = "block"
	Warn  Action = "warn"
)

// Rule names of the built-in leak rules.
const (
	RuleToken       = "token"        // the Forgejo token value
	RuleForgejoHost = "forgejo-host" // the Forgejo host name (root_url, api_url)
)

// Match is one hit of the Matcher.
type Match struct {
	Rule       string
	Action     Action
	Start, End int
}

// Matcher finds the fixed leak rules: the token and the Forgejo host names
// (always block, no exceptions) and the configured leak_patterns. It is
// shared by the gates (over the publish set) and the output lint (over the
// staged site), so both enforce exactly the same rules.
type Matcher struct {
	token string
	rules []patternRule
}

type patternRule struct {
	name   string
	action Action
	re     *regexp.Regexp
}

// NewMatcher builds the matcher for cfg. token may be empty (tests).
func NewMatcher(cfg *config.Config, token string) (*Matcher, error) {
	m := &Matcher{token: token}
	for _, h := range ForgejoHosts(cfg) {
		// Case-insensitive, not part of a longer name (a subdomain of the
		// host still matches: it leaks the same internal name).
		re, err := regexp.Compile(`(?i)(?:^|[^a-z0-9-])(` + regexp.QuoteMeta(h) + `)(?:$|[^a-z0-9-])`)
		if err != nil {
			return nil, err
		}
		m.rules = append(m.rules, patternRule{name: RuleForgejoHost, action: Block, re: re})
	}
	for i, p := range cfg.Gates.LeakPatterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, err
		}
		m.rules = append(m.rules, patternRule{name: "leak_patterns[" + itoa(i) + "]", action: Action(p.Action), re: re})
	}
	return m, nil
}

// ForgejoHosts returns the Forgejo host names that must never be published:
// those of root_url and api_url, except loopback addresses.
func ForgejoHosts(cfg *config.Config) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, raw := range []string{cfg.Forgejo.RootURL, cfg.Forgejo.APIURL} {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if h == "" || h == "localhost" || seen[h] {
			continue
		}
		if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	return hosts
}

// Find returns every match in data, in rule order.
func (m *Matcher) Find(data []byte) []Match {
	var out []Match
	if m.token != "" {
		s := string(data)
		for off := 0; ; {
			i := strings.Index(s[off:], m.token)
			if i < 0 {
				break
			}
			out = append(out, Match{Rule: RuleToken, Action: Block, Start: off + i, End: off + i + len(m.token)})
			off += i + len(m.token)
		}
	}
	for _, r := range m.rules {
		for _, loc := range r.re.FindAllSubmatchIndex(data, 100) {
			start, end := loc[0], loc[1]
			if len(loc) >= 4 && loc[2] >= 0 {
				start, end = loc[2], loc[3]
			}
			out = append(out, Match{Rule: r.name, Action: r.action, Start: start, End: end})
		}
	}
	return out
}

// Blocks reports whether data contains anything that blocks publishing.
func (m *Matcher) Blocks(data []byte) (string, bool) {
	for _, x := range m.Find(data) {
		if x.Action == Block {
			return x.Rule, true
		}
	}
	return "", false
}

// Display is how a match may be shown in reports: never the token, and
// other matches truncated.
func (m *Matcher) Display(x Match, data []byte) string {
	if x.Rule == RuleToken {
		return "<token>"
	}
	return excerpt(string(data[x.Start:x.End]), 60)
}

func excerpt(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len([]rune(s)) > n {
		return string([]rune(s)[:n]) + "…"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
