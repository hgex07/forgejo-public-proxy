// SPDX-License-Identifier: AGPL-3.0-or-later

package credential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, data string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFrom(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "ok", "  abc123\n", 0o600)
	write(t, dir, "ro", "x", 0o400)
	write(t, dir, "open", "x", 0o644)
	write(t, dir, "blank", " \n", 0o600)
	write(t, dir, "big", strings.Repeat("a", maxBytes+1), 0o600)
	if err := os.Symlink(filepath.Join(dir, "ok"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}

	if b, err := LoadFrom(dir, "ok"); err != nil || string(b) != "abc123" {
		t.Fatalf("ok: %q %v", b, err)
	}
	if _, err := LoadFrom(dir, "ro"); err != nil {
		t.Fatalf("ro: %v", err)
	}
	for name, want := range map[string]string{
		"open":    "group/others",
		"blank":   "empty",
		"big":     "larger",
		"link":    "symlink",
		"sub":     "regular",
		"missing": "no such file",
		"../ok":   "invalid name",
		".hidden": "invalid name",
		"a/b":     "invalid name",
		"":        "invalid name",
		"-x":      "invalid name",
	} {
		_, err := LoadFrom(dir, name)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want error containing %q", name, err, want)
		}
	}
}

func TestLoadEnv(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "tok", "secret-token_1\n", 0o600)
	write(t, dir, "bad", "two words", 0o600)
	write(t, dir, "crlf", "a\r\nInjected: 1", 0o600)
	t.Setenv(EnvDir, "")
	if _, err := Token("tok"); err == nil || !strings.Contains(err.Error(), EnvDir) {
		t.Fatalf("unset dir: %v", err)
	}
	t.Setenv(EnvDir, dir)
	if s, err := Token("tok"); err != nil || s != "secret-token_1" {
		t.Fatalf("tok: %q %v", s, err)
	}
	for _, n := range []string{"bad", "crlf"} {
		if _, err := Token(n); err == nil {
			t.Errorf("%s: accepted", n)
		}
	}
}

func TestErrorsNeverContainSecret(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "bad", "s3cr3t value", 0o600)
	t.Setenv(EnvDir, dir)
	_, err := Token("bad")
	if err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("got %v", err)
	}
}
