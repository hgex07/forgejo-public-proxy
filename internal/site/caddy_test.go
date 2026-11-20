// SPDX-License-Identifier: AGPL-3.0-or-later

package site

import (
	"strings"
	"testing"
)

func TestCaddySite(t *testing.T) {
	out, err := CaddySite("fpp.example.com", "/srv/sites/fpp/current")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"http://fpp.example.com:8080 {", "root * /srv/sites/fpp/current",
		q(SiteCSP), q(RawCSP), q(MediaCSP), q(PermissionsPolicy), q(CacheShort), q(CacheImmutable),
		"respond 405", "handle_errors 404", "hide .fpp-site", `"image/svg+xml"`} {
		if !strings.Contains(out, want) {
			t.Errorf("generated site lacks %q", want)
		}
	}
	// Caddy defers a header block that contains a deletion and applies it
	// last, which would silently override every later directive. Deletions
	// must therefore stay on their own `header [@m] -Field` lines.
	inBlock := false
	for i, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, "header") && strings.HasSuffix(l, "{"):
			inBlock = true
		case l == "}":
			inBlock = false
		case inBlock && strings.HasPrefix(l, "-"):
			t.Errorf("line %d: deletion inside a header block: %q", i+1, l)
		}
	}
	if strings.Contains(out, "browse") {
		t.Error("directory listings enabled")
	}
	for _, bad := range [][2]string{{"Fpp.example.com", "/x"}, {"x.com\n}", "/x"}, {"x.com", "rel"}, {"x.com", "/a b"}, {"x.com", "/a/../b"}, {"x.com", "/a{b}"}} {
		if _, err := CaddySite(bad[0], bad[1]); err == nil {
			t.Errorf("accepted %q %q", bad[0], bad[1])
		}
	}
}
