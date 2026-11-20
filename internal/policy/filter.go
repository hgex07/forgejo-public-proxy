// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bmatcuk/doublestar/v4"

	"fpp/internal/config"
	"fpp/internal/gitx"
)

func authorName(pol config.Effective, name string) string {
	if pol.Authors == "hidden" {
		return ""
	}
	return cleanText([]byte(name))
}

func dateOf(pol config.Effective, t time.Time) time.Time {
	t = t.UTC()
	if pol.Dates == "exact" {
		return t
	}
	return t.Truncate(24 * time.Hour)
}

// cleanText makes text valid UTF-8 and drops NULs; escaping is the renderer's job.
func cleanText(b []byte) string {
	return strings.ReplaceAll(strings.ToValidUTF8(string(b), "�"), "\x00", "")
}

// sanitizeName makes a name safe to print in the local exposure report.
func sanitizeName(s string) string {
	s = strings.ToValidUTF8(s, "�")
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || isFormat(r) {
			return '?'
		}
		return r
	}, s)
}

func isFormat(r rune) bool { return unicode.Is(unicode.Cf, r) }

// pathProblem returns why a repo path cannot be published, or "".
func pathProblem(p string) string {
	if p == "" {
		return "empty path"
	}
	if !utf8.ValidString(p) {
		return "path is not valid UTF-8"
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return "path contains control characters"
		}
	}
	for _, seg := range strings.Split(p, "/") {
		switch {
		case seg == "" || seg == "." || seg == "..":
			return "path has an empty, . or .. segment"
		case len(seg) > 255:
			return "path segment longer than 255 bytes"
		case strings.EqualFold(seg, ".git"):
			return "path contains a .git segment"
		}
	}
	return ""
}

// excluded reports whether p, or any directory containing it, matches one
// of the exclude globs. Matching ignores case: excluding too much is safe,
// and `.ENV` or `Server.PEM` must not slip past `**/.env*` or `**/*.pem`.
func excluded(p string, globs []string) bool {
	p = strings.ToLower(p)
	for {
		for _, g := range globs {
			if ok, _ := doublestar.Match(strings.ToLower(g), p); ok {
				return true
			}
		}
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			return false
		}
		p = p[:i]
	}
}

// filterTree applies path rules, excludes and the raw size limit.
func filterTree(entries []gitx.TreeEntry, exclude []string, rawMax int64) ([]File, []Skip) {
	var files []File
	var skips []Skip
	for _, e := range entries {
		p := string(e.Path)
		if why := pathProblem(p); why != "" {
			skips = append(skips, Skip{Path: sanitizeName(p), Reason: why})
			continue
		}
		if excluded(p, exclude) {
			skips = append(skips, Skip{Path: p, Reason: "excluded"})
			continue
		}
		var kind FileKind
		switch {
		case e.Type == "commit" && e.Mode == "160000":
			kind = Submodule
		case e.Type != "blob":
			skips = append(skips, Skip{Path: p, Reason: "unsupported object type " + sanitizeName(e.Type)})
			continue
		case e.Mode == "120000":
			kind = Symlink
		case e.Mode == "100755":
			kind = Executable
		case e.Mode == "100644":
			kind = Regular
		default:
			skips = append(skips, Skip{Path: p, Reason: "unsupported file mode " + sanitizeName(e.Mode)})
			continue
		}
		if kind != Submodule && e.Size > rawMax {
			skips = append(skips, Skip{Path: p, Reason: "larger than raw_max_bytes"})
			continue
		}
		files = append(files, File{Path: p, Kind: kind, OID: e.OID, Size: e.Size})
	}
	return files, skips
}

// versionLess orders tag names like `git tag --sort=version:refname`:
// digit runs compare numerically, everything else bytewise.
func versionLess(a, b string) bool {
	for a != "" && b != "" {
		da, db := isDigit(a[0]), isDigit(b[0])
		if da && db {
			na, ra := digitRun(a)
			nb, rb := digitRun(b)
			ta, tb := strings.TrimLeft(na, "0"), strings.TrimLeft(nb, "0")
			if len(ta) != len(tb) {
				return len(ta) < len(tb)
			}
			if ta != tb {
				return ta < tb
			}
			a, b = ra, rb
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func digitRun(s string) (string, string) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return s[:i], s[i:]
}
