// SPDX-License-Identifier: AGPL-3.0-or-later

package site

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// BuildFile is the top-level file holding the build ID. After a deploy the
// operator compares it on the public site with what `fpp apply` printed:
// the builder cannot read anything back from the DMZ, so this is how an
// unpublish (or any change) is confirmed to be live.
const BuildFile = "build.txt"

// buildID hashes every file written so far (paths and bytes). Generation
// is deterministic, so identical output gives the same ID, and any change
// to what is served (a removed repo or file, diffs or authors turned off,
// edited release notes, a new template) gives a new one. It is computed
// before BuildFile itself is written.
func (w *writer) buildID() (string, error) {
	names := make([]string, 0, len(w.files))
	for f := range w.files {
		if f != MarkerFile {
			names = append(names, f)
		}
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		f, err := w.root.Open(name)
		if err != nil {
			return "", err
		}
		fh := sha256.New()
		_, err = io.Copy(fh, f)
		f.Close()
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\x00%x\x00", name, fh.Sum(nil))
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

// ReadBuildID returns the build ID of a generated site directory.
func ReadBuildID(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, BuildFile))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
