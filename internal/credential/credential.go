// SPDX-License-Identifier: AGPL-3.0-or-later

// Package credential loads secrets by name from the directory systemd exposes
// as $CREDENTIALS_DIRECTORY (LoadCredential=). Outside systemd (a dev shell or
// a CI runner) point CREDENTIALS_DIRECTORY at a 0700 directory holding one
// 0600 file per credential.
//
// Secrets never come from argv, the config file or plain environment values.
package credential

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// EnvDir is the environment variable naming the credentials directory.
const EnvDir = "CREDENTIALS_DIRECTORY"

const maxBytes = 16 << 10

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// Load reads credential name from $CREDENTIALS_DIRECTORY. Surrounding
// whitespace is trimmed. The file must be a regular file (not a symlink) that
// is not readable by group or others.
func Load(name string) ([]byte, error) {
	dir := os.Getenv(EnvDir)
	if dir == "" {
		return nil, fmt.Errorf("credential %q: $%s is not set (systemd LoadCredential=, or a 0700 dir for local runs)", name, EnvDir)
	}
	return LoadFrom(dir, name)
}

// LoadFrom is Load with an explicit directory.
func LoadFrom(dir, name string) ([]byte, error) {
	if !nameRe.MatchString(name) {
		return nil, fmt.Errorf("credential %q: invalid name", name)
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("credential %q: is a symlink", name)
		}
		return nil, fmt.Errorf("credential %q: %w", name, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("credential %q: %w", name, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("credential %q: not a regular file", name)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("credential %q: mode %04o is accessible by group/others; chmod 600", name, st.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("credential %q: %w", name, err)
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("credential %q: larger than %d bytes", name, maxBytes)
	}
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil, fmt.Errorf("credential %q: empty", name)
	}
	return data, nil
}

// Token loads a credential that will be sent in an HTTP header and checks it
// is a single token of printable ASCII, so it cannot inject header lines.
func Token(name string) (string, error) {
	b, err := Load(name)
	if err != nil {
		return "", err
	}
	return checkToken(name, b)
}

func checkToken(name string, b []byte) (string, error) {
	for _, c := range b {
		if c <= 0x20 || c >= 0x7f {
			return "", fmt.Errorf("credential %q: token must be printable ASCII without whitespace", name)
		}
	}
	return string(b), nil
}

// Path checks credential name like Load and returns its path, for tools that
// must open the file themselves (ssh -i). The secret is not read here.
func Path(name string) (string, error) {
	dir := os.Getenv(EnvDir)
	if dir == "" {
		return "", fmt.Errorf("credential %q: $%s is not set", name, EnvDir)
	}
	if _, err := LoadFrom(dir, name); err != nil {
		return "", err
	}
	p, err := filepath.Abs(filepath.Join(dir, name))
	if err != nil {
		return "", err
	}
	return p, nil
}
