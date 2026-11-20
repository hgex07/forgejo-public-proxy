// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestCheckConfigExample(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"check-config", "-config", "../../deploy/builder/config.example.yaml", "-print"}, &out, &errb)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "infra/homelab-scripts → /tools/homelab/") {
		t.Errorf("missing effective policy in output:\n%s", out.String())
	}
}

func TestCheckConfigStrictWarnings(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"check-config", "-strict", "-config", "../../deploy/builder/config.example.yaml"}, &out, &errb)
	if code != exitInvalid {
		t.Fatalf("exit %d, want %d (example has a releases warning)", code, exitInvalid)
	}
}

func TestCheckConfigInvalid(t *testing.T) {
	p := t.TempDir() + "/c.yaml"
	if err := os.WriteFile(p, []byte("site: { title: x, nope: 1 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"check-config", "-config", p}, &out, &errb); code != exitInvalid {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "error:") {
		t.Errorf("stderr = %q", errb.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"frobnicate"}, &out, &errb); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
}

func TestPlanNeedsCredential(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir())
	var out, errb bytes.Buffer
	code := run([]string{"plan", "-config", "../../deploy/builder/config.example.yaml", "-state", t.TempDir()}, &out, &errb)
	if code != exitInvalid || !strings.Contains(errb.String(), `credential "forgejo-token"`) {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if code := run([]string{"plan", "extra"}, &out, &errb); code != exitUsage {
		t.Fatalf("extra args: exit %d", code)
	}
}

func TestTermSafe(t *testing.T) {
	var b strings.Builder
	w := termSafe(&b)
	desc := "ok\x1b[2K\x1b]52;c;aGk=\x07 \u009b31m \u202eevil\u202c\r\tcafé ✓\n"
	// Split a multi-byte rune across writes, as an rsync pipe may.
	mid := strings.Index(desc, "é") + 1
	for _, part := range []string{desc[:mid], desc[mid:], "\xff\n"} {
		if _, err := w.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	want := "ok?[2K?]52;c;aGk=? ?31m ?evil??\tcafé ✓\n?\n"
	if b.String() != want {
		t.Errorf("got %q\nwant %q", b.String(), want)
	}
}
