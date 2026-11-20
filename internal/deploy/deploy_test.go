// SPDX-License-Identifier: AGPL-3.0-or-later

package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHCommand(t *testing.T) {
	ok := Options{Target: "deploy-x@192.0.2.10", Port: 2222, KeyFile: "/run/credentials/k", KnownHosts: "/etc/fpp/kh", Home: "/var/lib/fpp/h"}
	cmd, err := sshCommand(ok)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-F /dev/null", "-i /run/credentials/k", "-p 2222", "IdentitiesOnly=yes", "IdentityAgent=none",
		"BatchMode=yes", "StrictHostKeyChecking=yes", "UserKnownHostsFile=/etc/fpp/kh", "GlobalKnownHostsFile=/dev/null"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("ssh command lacks %q: %s", want, cmd)
		}
	}
	bad := []func(o *Options){
		func(o *Options) { o.Target = "host" },
		func(o *Options) { o.Target = "-oProxyCommand=x@h" },
		func(o *Options) { o.Target = "u@h:/etc" },
		func(o *Options) { o.Target = "u@h x" },
		func(o *Options) { o.KeyFile = "relative" },
		func(o *Options) { o.KnownHosts = "/a b" },
		func(o *Options) { o.Port = 0 },
	}
	for i, f := range bad {
		o := ok
		f(&o)
		if _, err := sshCommand(o); err == nil {
			t.Errorf("case %d accepted: %+v", i, o)
		}
	}
}

func TestDigest(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("index.html", "a")
	write("x/y.txt", "b")
	d1, err := Digest(dir)
	if err != nil {
		t.Fatal(err)
	}
	write(".fpp-site", "marker") // excluded from uploads, so from the digest
	if d2, _ := Digest(dir); d2 != d1 {
		t.Error("excluded file changed the digest")
	}
	write("x/y.txt", "c")
	if d3, _ := Digest(dir); d3 == d1 {
		t.Error("content change not detected")
	}
	write("x/y.txt", "b")
	if err := os.Rename(filepath.Join(dir, "x/y.txt"), filepath.Join(dir, "x/z.txt")); err != nil {
		t.Fatal(err)
	}
	if d4, _ := Digest(dir); d4 == d1 {
		t.Error("rename not detected")
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "l")); err != nil {
		t.Fatal(err)
	}
	if _, err := Digest(dir); err == nil {
		t.Error("symlink accepted")
	}
}
