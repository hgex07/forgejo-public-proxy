// SPDX-License-Identifier: AGPL-3.0-or-later

// Package deploy pushes a staged, linted site to the web host
// (docs/SETUP.md §6): rsync over SSH into the site's write-only incoming/
// directory (rrsync -wo on the other side), then a `ready` marker. The host
// validates the upload and activates it as a new release on its own; the
// builder can't read anything back.
package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Options configure a push.
type Options struct {
	Target     string // user@host
	Port       int
	KeyFile    string // private key (from the credentials directory)
	KnownHosts string // pinned host key(s)
	// Home is an empty private directory used as $HOME, so no ~/.ssh
	// config, agent or known_hosts can interfere.
	Home string
	// Timeout bounds the whole push (default 15 min).
	Timeout time.Duration
}

// Exclude lists site files that are never uploaded.
var Exclude = []string{"/.fpp-site"}

// Push uploads siteDir to <target>:staging/ (deleting what is no longer
// there) and then the ready marker.
func Push(ctx context.Context, o Options, siteDir string, log io.Writer) error {
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	ssh, err := sshCommand(o)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(siteDir)
	if err != nil || !fi.IsDir() {
		return fmt.Errorf("deploy: %s is not a directory", siteDir)
	}
	args := []string{"--archive", "--delete", "--delete-delay", "--checksum", "--chmod=D755,F644",
		"--no-owner", "--no-group", "--timeout=120", "--compress", "--stats", "-e", ssh}
	for _, x := range Exclude {
		args = append(args, "--exclude="+x)
	}
	args = append(args, "--", strings.TrimSuffix(siteDir, "/")+"/", o.Target+":staging/")
	if err := rsync(ctx, o, args, log); err != nil {
		return fmt.Errorf("deploy: upload: %w", err)
	}
	// The marker is sent as the content of a directory: rrsync rejects a
	// single-file destination that already exists ("could not make way").
	markerDir := filepath.Join(o.Home, "marker")
	if err := os.RemoveAll(markerDir); err != nil {
		return err
	}
	if err := os.Mkdir(markerDir, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(markerDir)
	if err := os.WriteFile(filepath.Join(markerDir, "ready"), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		return err
	}
	if err := rsync(ctx, o, []string{"--recursive", "--chmod=D755,F644", "--timeout=60", "-e", ssh, "--",
		markerDir + "/", o.Target + ":./"}, io.Discard); err != nil {
		return fmt.Errorf("deploy: ready marker: %w", err)
	}
	return nil
}

// sshCommand builds rsync's -e: no user config, no agent, only the deploy
// key, strict pinned host keys.
func sshCommand(o Options) (string, error) {
	user, host, ok := strings.Cut(o.Target, "@")
	if !ok || user == "" || host == "" || strings.ContainsAny(o.Target, " \t\n'\"\\:/") || strings.HasPrefix(o.Target, "-") {
		return "", errors.New("deploy: target must be user@host")
	}
	for _, p := range []string{o.KeyFile, o.KnownHosts, o.Home} {
		if !filepath.IsAbs(p) || strings.ContainsAny(p, " \t\n'\"\\") {
			return "", fmt.Errorf("deploy: path %q must be absolute without spaces or quotes", p)
		}
	}
	if o.Port <= 0 || o.Port > 65535 {
		return "", errors.New("deploy: invalid port")
	}
	return strings.Join([]string{"ssh", "-F", "/dev/null", "-i", o.KeyFile, "-p", strconv.Itoa(o.Port),
		"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + o.KnownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no", "-o", "CheckHostIP=no",
		"-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
		"-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes",
		"-o", "LogLevel=ERROR"}, " "), nil
}

func rsync(ctx context.Context, o Options, args []string, log io.Writer) error {
	cmd := exec.CommandContext(ctx, "rsync", args...)
	cmd.Env = []string{"HOME=" + o.Home, "PATH=/usr/local/bin:/usr/bin:/bin", "LC_ALL=C"}
	cmd.Dir = o.Home
	var stderr bytes.Buffer
	cmd.Stdout = log
	cmd.Stderr = &stderr
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 2000 {
			msg = msg[:2000] + "…"
		}
		return fmt.Errorf("%w: %s", err, msg)
	}
	return nil
}

// Digest identifies a site tree's content (paths and file bytes, minus
// Exclude), so an unchanged build can skip the upload and the host keeps
// its current release.
func Digest(dir string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		for _, x := range Exclude {
			if "/"+filepath.ToSlash(rel) == x {
				return nil
			}
		}
		if d.IsDir() {
			fmt.Fprintf(h, "d %s\x00", rel)
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("deploy: %s is not a regular file", rel)
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		fh := sha256.New()
		if _, err := io.Copy(fh, f); err != nil {
			return err
		}
		fmt.Fprintf(h, "f %s\x00%x\x00", rel, fh.Sum(nil))
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
