// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"fpp/internal/config"
)

func TestPathProblem(t *testing.T) {
	for p, bad := range map[string]bool{
		"a/b.go": false, "ünï/çødé": false, ".github/x": false,
		"": true, "a//b": true, "a/./b": true, "../x": true, "a\x01b": true, "a\nb": true,
		"\xff": true, ".git/config": true, "a/.GIT/x": true, strings.Repeat("a", 256): true,
		"a\u0085b": true,
	} {
		if got := pathProblem(p) != ""; got != bad {
			t.Errorf("pathProblem(%q) bad=%v, want %v", p, got, bad)
		}
	}
}

func TestExcluded(t *testing.T) {
	globs := append(append([]string(nil), config.BuiltinExclude...), "secret/**", "docs/private")
	for p, want := range map[string]bool{
		".env": true, "a/b/.env.local": true, "x/server.pem": true, "home/.ssh/id_ed25519.pub": true,
		".envrc.d/file": true, "secret/a/b": true, "docs/private/x.md": true, "docs/private": true,
		"src/env.go": false, "docs/privateer.md": false, "README.md": false, "keys.go": false,
		// Case-insensitive: the denylist must not be bypassed by capitals.
		".ENV": true, "conf/Server.PEM": true, "sub/ID_RSA": true, "Secret/x": true, "DOCS/Private/y": true,
	} {
		if got := excluded(p, globs); got != want {
			t.Errorf("excluded(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestVersionSort(t *testing.T) {
	tags := []string{"v1.10", "v1.2", "v1.9.1", "v2.0-rc1", "v10.0", "v1.02", "v1.0"}
	sort.Slice(tags, func(i, j int) bool { return versionLess(tags[i], tags[j]) })
	want := []string{"v1.0", "v1.2", "v1.02", "v1.9.1", "v1.10", "v2.0-rc1", "v10.0"}
	if !slices.Equal(tags, want) {
		t.Errorf("got %v want %v", tags, want)
	}
}

func TestPolicyText(t *testing.T) {
	ts := time.Date(2024, 3, 4, 23, 59, 1, 0, time.FixedZone("x", -5*3600))
	day := config.Effective{Dates: "day", Authors: "names"}
	if got := dateOf(day, ts); !got.Equal(time.Date(2024, 3, 5, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("day: %v", got)
	}
	exact := config.Effective{Dates: "exact", Authors: "hidden"}
	if got := dateOf(exact, ts); !got.Equal(ts) || got.Location() != time.UTC {
		t.Errorf("exact: %v", got)
	}
	if authorName(exact, "A") != "" || authorName(day, "A\xff") != "A�" {
		t.Error("authorName")
	}
	if cleanText([]byte("a\x00b\xc0")) != "ab�" {
		t.Error("cleanText")
	}
}

// TestExcludedHostSpecificFiles pins the excludes used to publish fpp itself
// (the operator's private config): host-specific deploy files stay private.
func TestExcludedHostSpecificFiles(t *testing.T) {
	globs := append(append([]string(nil), config.BuiltinExclude...),
		"docs/DMZ.md", "deploy/dmz/**", "deploy/builder/fpp-apply*.service", "deploy/builder/fpp-egress.*")
	for p, want := range map[string]bool{
		"docs/DMZ.md": true, "deploy/dmz/proxmox/dmz.nft": true, "deploy/dmz/vm/quadlet/caddy.container": true,
		"deploy/dmz": true, "deploy/builder/fpp-apply.service": true, "deploy/builder/fpp-apply-manual.service": true,
		"deploy/builder/fpp-egress.nft": true, "deploy/builder/fpp-egress.service": true,
		"deploy/builder/config.example.yaml": false, "deploy/builder/fpp-apply.timer": false,
		"docs/SETUP.md": false, "docs/RUNBOOK.md": false,
	} {
		if got := excluded(p, globs); got != want {
			t.Errorf("excluded(%q) = %v, want %v", p, got, want)
		}
	}
}
